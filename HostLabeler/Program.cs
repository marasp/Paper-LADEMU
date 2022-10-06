using System;
using System.Collections.Generic;
using System.IO;
using loglabel.Models;
using Newtonsoft.Json;

/// <summary>
/// It reads the lines of a file, deserializes each line into a WinlogBeat object, and adds each object
/// to a list
/// </summary>
/// <param name="path">The path to the file you want to read.</param>
/// <returns>
/// A list of WinlogBeat objects.
/// </returns>
List<WinlogBeat> GetWinLogBeats(string path)
{
    IEnumerable<string> winLogBeatReadLines = File.ReadLines(path);
    var winlogBeats = new List<WinlogBeat>();

    var i = 0;

    foreach (var winLogBeat in winLogBeatReadLines)
    {
        try
        {
            i += 1;
            var deserializedWinLogBeat = JsonConvert.DeserializeObject<WinlogBeat>(winLogBeat);
            if (deserializedWinLogBeat != null) winlogBeats.Add(deserializedWinLogBeat);
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
        }
    }

    return winlogBeats;
}

/// <summary>
/// It reads a JSON file and returns a list of malicious operations
/// </summary>
/// <param name="path">The path to the malicious operations file.</param>
/// <returns>
/// A list of malicious operations.
/// </returns>
IEnumerable<MaliciousOperation>? GetMaliciousOperations(string path)
{
    IEnumerable<MaliciousOperation>? maliciousOperations =
        JsonConvert.DeserializeObject<List<MaliciousOperation>>(File.ReadAllText(path));
    return maliciousOperations;
}

//PROGRAM STARTS HERE
var winLogBeats = GetWinLogBeats(System.IO.Directory.GetParent() + System.IO.Path.Join("Datasets", "RawLogs", "winlogbeat.json"));
var maliciousOperations = GetMaliciousOperations(System.IO.Directory.GetParent() + System.IO.Path.Join("Datasets", "RawLogs", "caldera-log.json"));

var logLabeler = new LogLabeler(winLogBeats, maliciousOperations);
logLabeler.FindAndMarkAllDescendantMaliciousOperations()
    .SaveJsonToFile(System.IO.Directory.GetParent() + System.IO.Path.Join("Datasets", "Labelled", "APT29-Host.json"))
    .PrintMaliciousOperationsIdentified();