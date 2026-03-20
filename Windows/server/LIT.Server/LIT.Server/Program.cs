using LIT.ServerMVC.Data;
using LIT.ServerMVC.Services;
using LIT.ServerMVC.Services.Implementation;
using Microsoft.EntityFrameworkCore;
using Serilog;
using Serilog.Events;

Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Verbose()
    .MinimumLevel.Override("Microsoft", LogEventLevel.Fatal)
    .MinimumLevel.Override("System", LogEventLevel.Fatal)
    .MinimumLevel.Override("Serilog", LogEventLevel.Fatal)
    .WriteTo.Console()
    .WriteTo.File(path: "logs/app-.log", rollingInterval: RollingInterval.Month, retainedFileCountLimit: 24, shared: true)
    .CreateLogger();

try
{
    var builder = WebApplication.CreateBuilder(args);

    builder.Host.UseSerilog();

    builder.Services.AddDbContext<ApplicationDbContext>(options =>
    {
        //Recreate migration if changing SQL

        //sql server database
        //options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"));

        //sqlite database
        options.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection"));
    });

    // Add services to the container.

    // API + MVC Controllers
    builder.Services.AddControllersWithViews();//.AddRazorRuntimeCompilation();

    builder.Services.AddAuthentication(o =>
    {
        o.DefaultAuthenticateScheme = "AppCookie";
        o.DefaultChallengeScheme = "AppCookie";
        o.DefaultSignInScheme = "AppCookie";
    })
    .AddCookie("AppCookie", o =>
    {
        o.LoginPath = "/Account/Login";
        o.LogoutPath = "/Account/Logout";
        o.ExpireTimeSpan = TimeSpan.FromMinutes(15);
        o.SlidingExpiration = true;
        //o.Cookie.HttpOnly = true;
    });

    builder.Services.AddAuthorization();

    builder.Services.AddSingleton<ICertificateGenerationService, CertificateGenerationService>();
    builder.Services.AddSingleton<ICertificateValidationService, CertificateValidationService>();
    var app = builder.Build();

    //automatic DB creation and migration
    using (var scope = app.Services.CreateScope())
    {
        var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        db.Database.Migrate();
    }

    // Configure the HTTP request pipeline.
    if (!app.Environment.IsDevelopment())
    {
        app.UseExceptionHandler("/Home/Error");
        // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
        app.UseHsts();
    }

    app.UseHttpsRedirection();
    app.UseStaticFiles();

    app.UseRouting();

    app.UseAuthentication();
    app.UseAuthorization();

    app.MapControllers();
    app.MapControllerRoute(
        name: "default",
        pattern: "{controller=Account}/{action=Login}/{id?}");

    app.Run();
}
catch (Exception ex)
{
    Log.CloseAndFlush();
}
