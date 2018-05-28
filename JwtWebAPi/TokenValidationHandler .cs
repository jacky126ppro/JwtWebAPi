using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using System.Web;

namespace JwtWebAPi
{
    internal class TokenValidationHandler:DelegatingHandler
    {
        private static bool TryRetievToken(HttpRequestMessage request,out string token)
        {
            token = null;
            IEnumerable<string> authzHeaders;

            if(!request.Headers.TryGetValues("Authorization",out authzHeaders) || authzHeaders.Count() > 1)
            {
                return false;
            }
            var bearerToken = authzHeaders.ElementAt(0);
            token = bearerToken.StartsWith("Bearer ") ? bearerToken.Substring(7) : bearerToken;
            return true;
        }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            HttpStatusCode statusCode;
            string token;

            if(!TryRetievToken(request ,out token))
            {
                statusCode = HttpStatusCode.Unauthorized;
                return base.SendAsync(request, cancellationToken);
            }

            try
            {
                const string sec = "4uce812b05hkoru2gtgatcb28l1yvdfpdxtso1tuc14ry4j4op4776flx69ipuxtxwbbouv61535gd0a8anmmsxa5dykxmj1o02i14f8f841ru16aeyndl384ry8jozy";
                var now = DateTime.UtcNow;
                var securityKey = new SymmetricSecurityKey(System.Text.Encoding.Default.GetBytes(sec));

                SecurityToken securityToken;
                JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
                TokenValidationParameters validationParameters = new TokenValidationParameters()
                {
                    ValidAudience = "http://localhost:12951",
                    ValidIssuer = "http://localhost:12951",
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    LifetimeValidator = LifetimeValidator,
                    IssuerSigningKey = securityKey

                };

                Thread.CurrentPrincipal = handler.ValidateToken(token, validationParameters, out securityToken);

                HttpContext.Current.User = handler.ValidateToken(token, validationParameters, out securityToken);

                return base.SendAsync(request, cancellationToken);

            }
            catch(SecurityTokenException e)
            {
                statusCode = HttpStatusCode.Unauthorized;
            }catch(Exception e)
            {
                statusCode = HttpStatusCode.Unauthorized;
            }
              return Task<HttpResponseMessage>.Factory.StartNew(() => new HttpResponseMessage(statusCode){ });
        }

        public bool LifetimeValidator(DateTime? notBefore,DateTime? expires,SecurityToken security,TokenValidationParameters validationParameters)
        {
            if (expires != null)
            {
                if (DateTime.UtcNow < expires) return true;
            }
            return false;
        }
    }
}