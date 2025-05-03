using JWT_LOGIN.Models;
using System;
using System.Data.SqlClient;
using System.Web;
using System.Web.Mvc;
 // Add the namespace where LoginViewModel is located

public class HomeController : Controller
{
    private string connectionString = @"Data Source=DESKTOP-3EU0K5K;Initial Catalog=Exprement;Integrated Security=True;"; // Use your actual database connection string

    // GET: Login
    public ActionResult Login()
    {
        // Check if the user is already logged in (i.e., check for a valid token in the cookies)
        var token = Request.Cookies["auth_token"]?.Value;

        if (!string.IsNullOrEmpty(token))
        {
            // Validate the token (using the helper method)
            var principal = JwtHelper.GetPrincipalFromExpiredToken(token);
            if (principal != null)
            {
                
                // If the token is valid, redirect the user to /secure/Index
                return RedirectToAction("Index", "Secure"); // Secure is the controller that needs authentication
            }
        }


        return View(new LoginViewModel()); // Pass an empty LoginViewModel to the view
    }

    // POST: Login
    [HttpPost]
    public ActionResult Login(LoginViewModel model)
    {
        if (ModelState.IsValid)
        {
            // Validate the credentials using ADO.NET
            using (SqlConnection conn = new SqlConnection(connectionString))
            {
                conn.Open();
                string query = "SELECT UserId, Role, Gender, MobileNumber, District FROM Users WHERE Username = @username AND Password = @password";
                SqlCommand cmd = new SqlCommand(query, conn);
                cmd.Parameters.AddWithValue("@username", model.Username);
                cmd.Parameters.AddWithValue("@password", model.Password); // For real applications, use hashed password comparisons.

                SqlDataReader reader = cmd.ExecuteReader();
                if (reader.Read())
                {
                    // Retrieve user details from the database
                    int userId = Convert.ToInt32(reader["UserId"]);
                    string role = reader["Role"].ToString();
                    string gender = reader["Gender"].ToString();
                    string mobileNumber = reader["MobileNumber"].ToString();
                    string district = reader["District"].ToString();

                    // Generate JWT token with additional claims
                    string token = JwtHelper.GenerateJwtToken(model.Username, userId, role, gender, mobileNumber, district);

                    // Store the token in a cookie
                    Response.Cookies["auth_token"].Value = token;
                    Response.Cookies["auth_token"].HttpOnly = true; // Prevent JS access
                    Response.Cookies["auth_token"].SameSite = SameSiteMode.Strict; // CSRF protection
                    Response.Cookies["auth_token"].Secure = true;
                    Response.Cookies["auth_token"].Expires = DateTime.Now.AddMinutes(30); // Token expiration time

                    return RedirectToAction("Index", "Secure"); // Redirect to another page after login
                }
                else
                {
                    ViewBag.Message = "Invalid username or password."; // If login fails
                    return View(model); // Return the model with error message
                }
            }
        }

        return View(model); // Return the model in case of invalid input
    }


    // Logout action to clear cookies and end the session
    public ActionResult Logout()
    {
        Response.Cookies["auth_token"].Expires = DateTime.Now.AddDays(-1); // Remove the token
        return RedirectToAction("Login");
    }

    public ActionResult About()
    {
        return View();
    }

    public ActionResult Contact()
    {
        return View();
    }
}
