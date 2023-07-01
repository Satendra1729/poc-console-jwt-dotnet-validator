using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

public class JwtGeneratorValidator
{
    public string GenerateJwtToken(string privateKeyFilename)
    {
        using (RSA rsa = RSA.Create())
        {
            rsa.ImportFromPem(File.ReadAllText(privateKeyFilename).ToCharArray());
            
            RSAParameters rsaParameters = rsa.ExportParameters(true);

            RsaSecurityKey rsaSecurityKey = new RsaSecurityKey(rsaParameters);

            Console.WriteLine($"Jwk Thumb Print {Convert.ToBase64String(rsaSecurityKey.ComputeJwkThumbprint())}"); 

            Claim[] claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, "subject"),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();

            SecurityTokenDescriptor tokenDescriptor = new SecurityTokenDescriptor
            {
                Issuer = "issuer",
                Audience = "audience",
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddSeconds(1),
                SigningCredentials = new SigningCredentials(
                rsaSecurityKey, SecurityAlgorithms.RsaSha256)
            };

            JwtSecurityToken token = tokenHandler.CreateJwtSecurityToken(tokenDescriptor);

            string jwtToken = tokenHandler.WriteToken(token);

            return jwtToken;
        }
    }

    public bool ValidateJwtToken(string jwtToken,string publicKeyFilename)
    {
        using (RSA rsa = RSA.Create())
        {
            RSAParameters rsaParameters = ReadPublicKey(publicKeyFilename);

            RsaSecurityKey rsaSecurityKey = new RsaSecurityKey(rsaParameters);

            JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();

            TokenValidationParameters validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = false,
                ValidateAudience = false,
                ValidIssuer = "https://iam-client-test.us-east.philips-healthsuite.com/oauth2/access_token",
                ValidAudience = "clientforsecmtest",
                IssuerSigningKey = rsaSecurityKey
            };

            try
            {
                ClaimsPrincipal claimsPrincipal = tokenHandler.ValidateToken(jwtToken, validationParameters, out var validateToken);
                return true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Token validation failed: {ex.Message}");
                return false;
            }
        }
        
    }
    private static RSAParameters ReadPublicKey(string publicKeyFilename)
    {
        string publicKeyText = File.ReadAllText(publicKeyFilename);
        PemReader pemReader = new PemReader(new StringReader(publicKeyText));
        object pemObject = pemReader.ReadObject();
        
        if (pemObject is AsymmetricKeyParameter asymmetricKeyParam)
        {
            RSAParameters publicKey = DotNetUtilities.ToRSAParameters((RsaKeyParameters)asymmetricKeyParam);
            return publicKey;
        }
        
        throw new InvalidOperationException("Invalid PEM file. Failed to read the public key.");
    }
}
