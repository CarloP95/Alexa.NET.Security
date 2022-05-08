using Alexa.NET.Request;
using Microsoft.AspNetCore.Http;
using System;
using System.IO;
using System.Threading.Tasks;

namespace Alexa.NET.Security.Middleware
{
    /// <summary>
    /// An ASP.NET Core Middleware for validating Alexa reqeusts
    /// </summary>
    public class AlexaRequestValidationMiddleware
    {
        private readonly RequestDelegate _next;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="next"></param>
        public AlexaRequestValidationMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        /// <summary>
        /// Validate if all necessary parts for a valid request are available
        /// and pass them to the ReqeustVerification tool
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        public async Task Invoke(HttpContext context)
        {
            context.Request.EnableBuffering();
            
            // Verify SignatureCertChainUrl is present
            context.Request.Headers.TryGetValue("SignatureCertChainUrl", out var signatureChainUrl);
            if (string.IsNullOrWhiteSpace(signatureChainUrl))
            {
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                return;
            }

            Uri certUrl;
            try
            {
                certUrl = new Uri(signatureChainUrl);
            }
            catch
            {
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                return;
            }

            // Verify SignatureCertChainUrl is Signature
            context.Request.Headers.TryGetValue("Signature", out var signature);
            if (string.IsNullOrWhiteSpace(signature))
            {
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                return;
            }

            string body = await new StreamReader(context.Request.Body).ReadToEndAsync();
            context.Request.Body.Position = 0;

            if (string.IsNullOrWhiteSpace(body))
            {
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                return;
            }
            var valid = await RequestVerification.Verify(signature, certUrl, body);
            if (!valid)
            {
                context.Response.StatusCode = StatusCodes.Status400BadRequest;
                return;
            }

            await _next(context);
        }
    }
}

