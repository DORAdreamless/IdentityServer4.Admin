using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Skoruba.IdentityServer4.Admin.Api.ExceptionHandling;
using System.Collections.Generic;

namespace Skoruba.IdentityServer4.Admin.Api.Controllers
{
    //[ApiController]
    [TypeFilter(typeof(ControllerExceptionFilterAttribute))]
    public class BaseController : ControllerBase
    {
        private readonly ILogger<BaseController> _logger;

        public BaseController(ILogger<BaseController> logger)
        {
            _logger = logger;
        }

        protected IActionResult Success(object model = null)
        {
            var result = new { success = true, data = model, message = "操作成功。", code = 200 };
            return new JsonResult(model);
        }
        protected IActionResult Fail(string message, int code = 400, object model = null)
        {
            var result = new { success = false, data = model, message = message, code = code };
            return new JsonResult(model);
        }
    }
}