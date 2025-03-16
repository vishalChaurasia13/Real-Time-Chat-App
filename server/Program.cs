using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Authorization;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using server.Data;
using Microsoft.EntityFrameworkCore; 
using BCrypt.Net;


var builder = WebApplication.CreateBuilder(args);
var jwtSettings = builder.Configuration.GetSection("JwtSettings");
string secretKey = jwtSettings["Key"] ?? throw new ArgumentNullException("JWT Key is missing from configuration.");
var key = Encoding.UTF8.GetBytes(secretKey);

//----------------------------------Allow access to send requests and responses from client-----------------------------

builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowFrontend", // Define a CORS policy named "AllowFrontend"
        policy =>
        {
            policy.WithOrigins("http://localhost:5173") // Allow requests from Vite's frontend
                  .AllowAnyMethod() // Allow all HTTP methods (GET, POST, PUT, DELETE, etc.)
                  .AllowAnyHeader() // Allow all headers (Authorization, Content-Type, etc.)
                  .AllowCredentials(); // Allow sending cookies or authorization headers (for JWT, sessions, etc.)
        });
});

// Add controllers to the app
builder.Services.AddControllers();

// Configure authentication
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.RequireHttpsMetadata = false;
        options.SaveToken = true;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(key),
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidIssuer = jwtSettings["Issuer"],
            ValidAudience = jwtSettings["Audience"],
            ValidateLifetime = true
        };
    });

builder.Services.AddAuthorization();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

//Database Connecton
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

var app = builder.Build();

// Configure middleware
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseCors("AllowFrontend");
app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();


var users = new List<User>(); // ✅ In-memory user list


// ✅ Register a new user
app.MapPost("/api/auth/register", async (AppDbContext db, [FromBody] User newUser) =>
{
    if (await db.Users.AnyAsync(u => u.Username == newUser.Username))
    {
        return Results.BadRequest(new { message = "Username already exists" });
    }

    newUser.Password = BCrypt.Net.BCrypt.HashPassword(newUser.Password); // Hash password
    db.Users.Add(newUser);
    await db.SaveChangesAsync();

    return Results.Ok(new { message = "Registration successful" });
});


// ✅ Login & Generate JWT Token
app.MapPost("/api/auth/login", async (AppDbContext db, [FromBody] UserCredentials credentials) =>
{
    var user = await db.Users.FirstOrDefaultAsync(u => u.Username == credentials.Username);
    if (user == null || !BCrypt.Net.BCrypt.Verify(credentials.Password, user.Password))
    {
        return Results.Unauthorized();
    }

    // ✅ Create JWT Token
    var tokenHandler = new JwtSecurityTokenHandler();
    var tokenDescriptor = new SecurityTokenDescriptor
    {
        Subject = new ClaimsIdentity(new[] { new Claim(ClaimTypes.Name, credentials.Username) }),
        Expires = DateTime.UtcNow.AddMinutes(60),
        Issuer = jwtSettings["Issuer"],
        Audience = jwtSettings["Audience"],
        SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
    };

    var token = tokenHandler.CreateToken(tokenDescriptor);
    return Results.Ok(new { Token = tokenHandler.WriteToken(token) });
});


// ✅ Protected Route Example (Requires JWT)
app.MapGet("/api/protected", (ClaimsPrincipal user) =>
{
    var username = user.Identity?.Name;
    return Results.Ok(new { message = $"Hello {username}, you accessed a protected route!" });
}).RequireAuthorization();

app.MapGet("/", () =>
{
    return Results.Ok("Hello, Client! This is a response from the server.");
});

app.MapGet("/api/users", () => Results.Ok(users));



app.Run();

// 🔹 **User Credentials Model**
record UserCredentials(string Username, string Password);