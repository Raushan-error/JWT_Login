using System.Web;
using System.Web.Mvc;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;

public class BaseController : Controller
{
    protected override void OnActionExecuting(ActionExecutingContext filterContext)
    {
        base.OnActionExecuting(filterContext);

        // Retrieve the token from cookies
        var token = Request.Cookies["auth_token"]?.Value;
        if (string.IsNullOrEmpty(token))
        {
            filterContext.Result = new RedirectResult(Url.Action("Login", "Home")); // Redirect to login if no token
            return;
        }

        try
        {
            // Try to validate the token
            var principal = JwtHelper.GetPrincipalFromExpiredToken(token);
            if (principal == null)
            {
                filterContext.Result = new RedirectResult(Url.Action("Login", "Home")); // Redirect to login if token is invalid
            }
            else
            {
                // Token is valid, attach user info to HttpContext (so it's available throughout the app)
                HttpContext.User = principal;
            }
        }
        catch
        {
            filterContext.Result = new RedirectResult(Url.Action("Login", "Home")); // Redirect to login if token validation fails
        }
    }
}
