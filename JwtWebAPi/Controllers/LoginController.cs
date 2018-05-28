using JwtWebAPi.Models;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Claims;
using System.Web.Http;

namespace JwtWebAPi.Controllers
{
    public class LoginController : ApiController
    {
        [HttpPost]
        public IHttpActionResult Authenticate([FromBody] LoginRequest login)
        {
            var loginResponse = new LoginResponse();
            LoginRequest loginRequest = new LoginRequest();
            loginRequest.Username = login.Username.ToLower();
            loginRequest.Password = login.Password;

            IHttpActionResult response;
            HttpResponseMessage responseMsg = new HttpResponseMessage();
            var isUsernamePasswordVaild = false;

            if (login != null)
                isUsernamePasswordVaild = loginRequest.Password == "admin" ? true : false;
                if (isUsernamePasswordVaild)
                {
                    string token = createToken(loginRequest.Username);
                    //return the token
                    return Ok(token);
                }
                else
                {
                    loginResponse.responseMsg.StatusCode = HttpStatusCode.Unauthorized;
                    response = ResponseMessage(loginResponse.responseMsg);
                    return response;
                }

        }

        private string createToken(string username)
        {
            DateTime issuedAt = DateTime.UtcNow;

            DateTime expires = DateTime.UtcNow.AddDays(7);

            var tokenHandler = new JwtSecurityTokenHandler();

            ClaimsIdentity claimsIdentity = new ClaimsIdentity(new[]
            {
                new Claim(ClaimTypes.Name ,username)
            });

            const string sec = "4uce812b05hkoru2gtgatcb28l1yvdfpdxtso1tuc14ry4j4op4776flx69ipuxtxwbbouv61535gd0a8anmmsxa5dykxmj1o02i14f8f841ru16aeyndl384ry8jozy";
            var now = DateTime.UtcNow;
            var securityKey = new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(System.Text.Encoding.Default.GetBytes(sec));
            var signingCredentials = new Microsoft.IdentityModel.Tokens.SigningCredentials(securityKey, Microsoft.IdentityModel.Tokens.SecurityAlgorithms.HmacSha256Signature);

            var token =
               (JwtSecurityToken)
                   tokenHandler.CreateJwtSecurityToken(
                       issuer: "http://localhost:12951",
                   audience: "http://localhost:12951",
                       subject: claimsIdentity, 
                       notBefore: issuedAt, 
                       expires: expires, 
                       signingCredentials: signingCredentials);
            var tokenString = tokenHandler.WriteToken(token);

            return tokenString;
        }
    }
}
