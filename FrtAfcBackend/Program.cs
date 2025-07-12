using DotNetEnv;

namespace FrtAfcBackend
{
    public class Program
    {
        public static void Main(string[] args)
        {
            // Load the environment variables from the .env file
            Env.Load();

            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.

            builder.Services.AddControllers();

            var app = builder.Build();

            // Configure the HTTP request pipeline.

            app.UseHttpsRedirection();

            app.UseAuthorization();


            app.MapControllers();

            app.Run();
        }
    }
}
