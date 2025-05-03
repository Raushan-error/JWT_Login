using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System;
using System.Linq;

public static class JwtHelper
{
    private static string SecretKey = @"GzJHjOw0AxK8D/VZRBbQc2DY8DffbHwDb8l0I4bBjME=\r\n";  // Secret key
    private static string Issuer = "YourIssuer";
    private static string Audience = "YourAudience";

    // Generate JWT Token (including user details like gender, mobile_number, district)
    public static string GenerateJwtToken(string username, int userId, string role, string gender, string mobileNumber, string district)
    {
        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(SecretKey));
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, username),
            new Claim("user_id", userId.ToString()),            // Custom claim for user ID
            new Claim(ClaimTypes.Role, role),                   // Custom claim for user role
            new Claim("gender", gender),                        // Custom claim for gender
            new Claim("mobile_number", mobileNumber),           // Custom claim for mobile number
            new Claim("district", district),                    // Custom claim for district
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()) // JWT ID - unique identifier for each token
        };

        var token = new JwtSecurityToken(Issuer, Audience, claims, expires: DateTime.Now.AddMinutes(30), signingCredentials: credentials);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    // Get claims from the token
    public static ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(SecretKey));

        var tokenValidationParameters = new TokenValidationParameters
        {
            ValidateAudience = false,
            ValidateIssuer = false,
            ValidateLifetime = false,  // Ignore the expiration date for validation
            IssuerSigningKey = securityKey
        };

        var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out var validatedToken);
        return principal;
    }

    // Extract user information from the token
    public static string GetUsernameFromToken(string token)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var jwtToken = tokenHandler.ReadToken(token) as JwtSecurityToken;

        if (jwtToken == null)
        {
            return null; // If the token is invalid, return null
        }

        var usernameClaim = jwtToken.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Sub);
        return usernameClaim?.Value;
    }

    // Extract user_id from the token
    public static int GetUserIdFromToken(string token)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var jwtToken = tokenHandler.ReadToken(token) as JwtSecurityToken;

        if (jwtToken == null)
        {
            return -1; // Return -1 if the token is invalid
        }

        var userIdClaim = jwtToken.Claims.FirstOrDefault(c => c.Type == "user_id");
        return userIdClaim != null ? Convert.ToInt32(userIdClaim.Value) : -1;
    }

    // Extract role from the token
    public static string GetRoleFromToken(string token)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var jwtToken = tokenHandler.ReadToken(token) as JwtSecurityToken;

        if (jwtToken == null)
        {
            return null; // Return null if the token is invalid
        }

        var roleClaim = jwtToken.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Role);
        return roleClaim?.Value;
    }

    // Extract gender from the token
    public static string GetGenderFromToken(string token)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var jwtToken = tokenHandler.ReadToken(token) as JwtSecurityToken;

        if (jwtToken == null)
        {
            return null; // Return null if the token is invalid
        }

        var genderClaim = jwtToken.Claims.FirstOrDefault(c => c.Type == "gender");
        return genderClaim?.Value;
    }

    // Extract mobile_number from the token
    public static string GetMobileNumberFromToken(string token)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var jwtToken = tokenHandler.ReadToken(token) as JwtSecurityToken;

        if (jwtToken == null)
        {
            return null; // Return null if the token is invalid
        }

        var mobileNumberClaim = jwtToken.Claims.FirstOrDefault(c => c.Type == "mobile_number");
        return mobileNumberClaim?.Value;
    }

    // Extract district from the token
    public static string GetDistrictFromToken(string token)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var jwtToken = tokenHandler.ReadToken(token) as JwtSecurityToken;

        if (jwtToken == null)
        {
            return null; // Return null if the token is invalid
        }

        var districtClaim = jwtToken.Claims.FirstOrDefault(c => c.Type == "district");
        return districtClaim?.Value;
    }
}
