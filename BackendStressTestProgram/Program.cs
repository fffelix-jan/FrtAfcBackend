using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Text;

namespace BackendStressTestProgram
{
    internal class Program
    {
        // Hardcoded test constants
        private const string ApiEndpoint = "http://127.0.0.1:5281/api/v1/afc/";
        private const string Username = "lxz";
        private const string Password = "lxz654321";
        private const string IssuingStation = "FLZ";
        private const int TicketType = 0; // Full fare
        private const int ValueCents = 200;
        private const int Parallelism = 200;
        private const int TotalTickets = 10000;

        static async Task Main(string[] args)
        {
            Console.WriteLine("=== Fare API Stress Test ===");
            Console.WriteLine($"API Endpoint: {ApiEndpoint}");
            Console.WriteLine($"Username: {Username}");
            Console.WriteLine($"Issuing Station: {IssuingStation}");
            Console.WriteLine($"Ticket Type: {TicketType}");
            Console.WriteLine($"Ticket Value: {ValueCents} cents");
            Console.WriteLine($"Parallelism: {Parallelism}");
            Console.WriteLine($"Total Tickets: {TotalTickets}");
            Console.WriteLine();
            Console.WriteLine("Press Enter to start the test...");
            Console.ReadLine();

            using (var httpClient = new HttpClient())
            {
                httpClient.BaseAddress = new Uri(ApiEndpoint);
                string basicAuth = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{Username}:{Password}"));
                httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", basicAuth);

                // Stage 1: Authentication Test
                Console.WriteLine("[Stage 1] Authentication Test...");
                var authSw = Stopwatch.StartNew();
                var authResponse = await httpClient.GetAsync("currentdatetime");
                authSw.Stop();
                if (!authResponse.IsSuccessStatusCode)
                {
                    Console.WriteLine($"[ERROR] Authentication failed. Status: {authResponse.StatusCode}");
                    return;
                }
                Console.WriteLine($"[OK] Authentication succeeded in {authSw.ElapsedMilliseconds} ms.");
                Console.WriteLine();

                // Stage 2: Single Ticket Issue Test
                Console.WriteLine("[Stage 2] Single Ticket Issue Test...");
                var singleSw = Stopwatch.StartNew();
                var singleResult = await IssueTicketAsync(httpClient);
                singleSw.Stop();
                if (singleResult.Success)
                {
                    Console.WriteLine($"[OK] Single ticket issued in {singleSw.ElapsedMilliseconds} ms. TicketNumber: {singleResult.TicketNumber}");
                }
                else
                {
                    Console.WriteLine($"[ERROR] Single ticket issue failed: {singleResult.Error}");
                }
                Console.WriteLine();

                // Stage 3: Parallel Ticket Issue Stress Test
                Console.WriteLine("[Stage 3] Parallel Ticket Issue Stress Test...");
                var timings = new List<long>();
                int successCount = 0, failCount = 0;
                List<string> errors = new List<string>();
                Stopwatch totalSw = Stopwatch.StartNew();

                using (SemaphoreSlim sem = new SemaphoreSlim(Parallelism))
                {
                    List<Task> tasks = new List<Task>();
                    for (int i = 0; i < TotalTickets; i++)
                    {
                        await sem.WaitAsync();
                        var sw = Stopwatch.StartNew();
                        var task = IssueTicketAsync(httpClient).ContinueWith(t =>
                        {
                            sw.Stop();
                            timings.Add(sw.ElapsedMilliseconds);
                            if (t.Result.Success)
                            {
                                Interlocked.Increment(ref successCount);
                            }
                            else
                            {
                                Interlocked.Increment(ref failCount);
                                lock (errors) { errors.Add(t.Result.Error); }
                            }
                            sem.Release();
                        });
                        tasks.Add(task);
                    }
                    await Task.WhenAll(tasks);
                }
                totalSw.Stop();

                // Stage 4: Metrics and Analysis
                Console.WriteLine();
                Console.WriteLine("[Stage 4] Metrics and Analysis");
                Console.WriteLine($"Total Requests: {TotalTickets}");
                Console.WriteLine($"Success: {successCount}");
                Console.WriteLine($"Failed: {failCount}");
                Console.WriteLine($"Total Time: {totalSw.Elapsed.TotalSeconds:F2} seconds");
                Console.WriteLine($"Tickets Per Second: {(totalSw.Elapsed.TotalSeconds > 0 ? successCount / totalSw.Elapsed.TotalSeconds : 0):F2}");
                Console.WriteLine($"Average Time per Request: {(timings.Count > 0 ? timings.Average() : 0):F2} ms");
                Console.WriteLine($"Min Time: {(timings.Count > 0 ? timings.Min() : 0)} ms");
                Console.WriteLine($"Max Time: {(timings.Count > 0 ? timings.Max() : 0)} ms");
                if (failCount > 0)
                {
                    Console.WriteLine("Sample Errors:");
                    foreach (var err in errors.GetRange(0, Math.Min(5, errors.Count)))
                        Console.WriteLine($"- {err}");
                }
                Console.WriteLine();

                // Stage 5: Sequential Ticket Issue Test
                Console.WriteLine("[Stage 5] Sequential Ticket Issue Test...");
                timings.Clear();
                successCount = 0;
                failCount = 0;
                errors.Clear();
                Stopwatch seqSw = Stopwatch.StartNew();
                for (int i = 0; i < Parallelism; i++)
                {
                    var sw = Stopwatch.StartNew();
                    var result = await IssueTicketAsync(httpClient);
                    sw.Stop();
                    timings.Add(sw.ElapsedMilliseconds);
                    if (result.Success)
                        successCount++;
                    else
                    {
                        failCount++;
                        errors.Add(result.Error);
                    }
                }
                seqSw.Stop();
                Console.WriteLine($"Sequential {Parallelism} requests: Success={successCount}, Failed={failCount}, TotalTime={seqSw.Elapsed.TotalSeconds:F2}s, Avg={timings.Average():F2}ms");
                if (failCount > 0)
                {
                    Console.WriteLine("Sample Errors:");
                    foreach (var err in errors.GetRange(0, Math.Min(5, errors.Count)))
                        Console.WriteLine($"- {err}");
                }
                Console.WriteLine();

                Console.WriteLine("=== Stress Test Complete ===");
                Console.WriteLine();
                Console.WriteLine("Press Enter to exit...");
                Console.ReadLine();
            }
        }

        // Helper for issuing a ticket
        private static async Task<TicketIssueResult> IssueTicketAsync(HttpClient httpClient)
        {
            try
            {
                var requestObj = new
                {
                    IssuingStation = IssuingStation,
                    ValueCents = ValueCents,
                    TicketType = TicketType
                };
                var json = System.Text.Json.JsonSerializer.Serialize(requestObj);
                var content = new StringContent(json, Encoding.UTF8, "application/json");
                var response = await httpClient.PostAsync("issueticket/full", content);
                if (!response.IsSuccessStatusCode)
                {
                    var error = await response.Content.ReadAsStringAsync();
                    return new TicketIssueResult { Success = false, Error = $"HTTP {response.StatusCode}: {error}" };
                }
                var respJson = await response.Content.ReadAsStringAsync();
                // Try to extract ticket number for logging
                string? ticketNumber = null;
                try
                {
                    using (var doc = System.Text.Json.JsonDocument.Parse(respJson))
                    {
                        if (doc.RootElement.TryGetProperty("TicketNumber", out var numProp))
                            ticketNumber = numProp.GetString();
                    }
                }
                catch { }
                return new TicketIssueResult { Success = true, TicketNumber = ticketNumber };
            }
            catch (Exception ex)
            {
                return new TicketIssueResult { Success = false, Error = ex.Message };
            }
        }

        public class TicketIssueResult
        {
            public bool Success { get; set; }
            public string? TicketNumber { get; set; }
            public string? Error { get; set; }
        }
    }
}