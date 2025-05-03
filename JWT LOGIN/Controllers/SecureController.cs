using System;
using System.Web.Mvc;
//using JWT_LOGIN.Helpers; // Assuming JwtHelper is in the Helpers namespace

public class SecureController : Controller
{
    // GET: Secure/Index
    public ActionResult Index()
    {
        var token = Request.Cookies["auth_token"]?.Value;

       

        if (string.IsNullOrEmpty(token) || JwtHelper.GetPrincipalFromExpiredToken(token)==null)
        {
            return RedirectToAction("Login", "Home"); // Redirect to login page if token is invalid
        }

        // Extract user details from the JWT token
        var username = JwtHelper.GetUsernameFromToken(token);
        var userId = JwtHelper.GetUserIdFromToken(token);
        var role = JwtHelper.GetRoleFromToken(token);
        var gender = JwtHelper.GetGenderFromToken(token);
        var mobileNumber = JwtHelper.GetMobileNumberFromToken(token);
        var district = JwtHelper.GetDistrictFromToken(token);

        // You can now pass these values to the view or use them in any way
        ViewBag.Username = username;
        ViewBag.UserId = userId;
        ViewBag.Role = role;
        ViewBag.Gender = gender;
        ViewBag.MobileNumber = mobileNumber;
        ViewBag.District = district;

        return View(); // You can pass these values to the view if needed
    }

    // You can create more actions here that would require the user to be authenticated.
}
