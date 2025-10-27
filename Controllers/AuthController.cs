using Microsoft.AspNetCore.Mvc;
using Server.Data;
using Server.DTOs;
using Server.Models;
using Microsoft.EntityFrameworkCore;

namespace Server.Controllers {
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase {
        private readonly AppDbContext _db;
        public AuthController(AppDbContext db) { _db = db; }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterDto dto) {
            if (string.IsNullOrWhiteSpace(dto.Username) || string.IsNullOrWhiteSpace(dto.Password))
                return BadRequest(new { message = "Username and password are required" });

            if (await _db.Users.AnyAsync(u => u.Username == dto.Username))
                return Conflict(new { message = "Username already taken" });

            string hashed = BCrypt.Net.BCrypt.HashPassword(dto.Password, workFactor: 12);

            var user = new User {
                Username = dto.Username,
                Email = dto.Email ?? "",
                PasswordHash = hashed
            };

            _db.Users.Add(user);
            await _db.SaveChangesAsync();

            return Ok(new { message = "Registered" });
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginDto dto) {
            if (string.IsNullOrWhiteSpace(dto.Username) || string.IsNullOrWhiteSpace(dto.Password))
                return Unauthorized(new { message = "Invalid credentials" });

            var user = await _db.Users.FirstOrDefaultAsync(u => u.Username == dto.Username);
            if (user == null) return Unauthorized(new { message = "Invalid credentials" });

            try {
                bool valid = BCrypt.Net.BCrypt.Verify(dto.Password, user.PasswordHash);
                if (!valid) return Unauthorized(new { message = "Invalid credentials" });
            } catch {
                return StatusCode(500, new { message = "Password verification error" });
            }

            return Ok(new { message = "Logged in" });
        }
    }
}
