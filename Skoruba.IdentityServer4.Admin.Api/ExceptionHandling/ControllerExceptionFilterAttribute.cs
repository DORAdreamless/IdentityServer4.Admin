using System.Collections.Generic;
using System.Linq;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
using Newtonsoft.Json;
using Skoruba.IdentityServer4.Admin.BusinessLogic.Shared.ExceptionHandling;


namespace Skoruba.IdentityServer4.Admin.Api.ExceptionHandling
{
    public class ControllerExceptionFilterAttribute : ExceptionFilterAttribute
    {
        //private readonly ITempDataDictionaryFactory _tempDataDictionaryFactory;
        //private readonly IModelMetadataProvider _modelMetadataProvider;

        //public ControllerExceptionFilterAttribute(ITempDataDictionaryFactory tempDataDictionaryFactory,
        //    IModelMetadataProvider modelMetadataProvider)
        //{
        //    _tempDataDictionaryFactory = tempDataDictionaryFactory;
        //    _modelMetadataProvider = modelMetadataProvider;
        //}

        public override void OnException(ExceptionContext context)
        {
            if (!(context.Exception is UserFriendlyErrorPageException) &&
                !(context.Exception is UserFriendlyViewException)) return;

            context.Result = new JsonResult(new { code=500,message=context.Exception.Message,data=context.ModelState,success=false });
        }
        
    }
}