

public class JwtGenerator
{
    public static void Main()
    {
        JwtGeneratorValidator jgv = new JwtGeneratorValidator(); 
        string token = jgv.GenerateJwtToken("keypair.pem"); 
        Console.WriteLine(token);

        File.WriteAllText("local_token.jwt",token);  

        Boolean isValid = jgv.ValidateJwtToken(File.ReadAllText("local_token.jwt"),"key.pub");

        Console.WriteLine($"Token is valid : {isValid}");  
    }
}
