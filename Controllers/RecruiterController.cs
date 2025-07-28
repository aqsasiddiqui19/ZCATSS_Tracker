using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace ZCATSS_Tracker.Controllers
{
    public class RecruiterController : Controller
    {

        public IActionResult Dashboard()
        {
            return View();      
        }

    }
}
