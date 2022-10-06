using System;
using System.Collections.Generic;
using loglabel.Extensions;
using loglabel.Models;
using Newtonsoft.Json;

public class Metadata
{
    public string? beat { get; set; }
    public string type { get; set; }
    public string version { get; set; }
}

public class Ecs
{
    public string version { get; set; }
}

public class Agent
{
    public string ephemeral_id { get; set; }
    public string id { get; set; }
    public string name { get; set; }
    public string type { get; set; }
    public string version { get; set; }
    public string hostname { get; set; }
}

public class Thread
{
    public int id { get; set; }
}

public class Parent
{
    public string executable { get; set; }
    public string command_line { get; set; }
    public string name { get; set; }
    public List<string> args { get; set; }
    public string entity_id { get; set; }
    public int pid { get; set; }
}

public class Process
{
    public int? pid { get; set; }
    public Thread thread { get; set; }
    public string entity_id { get; set; }
    public string executable { get; set; }
    public string name { get; set; }
    public string param2 { get; set; }
    public Parent parent { get; set; }
}

public class Os
{
    public string version { get; set; }
    public string family { get; set; }
    public string name { get; set; }
    public string kernel { get; set; }
    public string build { get; set; }
    public string type { get; set; }
    public string platform { get; set; }
}

public class Host
{
    public Os os { get; set; }
    public string id { get; set; }
    public List<string> ip { get; set; }
    public string name { get; set; }
    public List<string> mac { get; set; }
    public string hostname { get; set; }
    public string architecture { get; set; }
}

public class EventData
{
    public string param2 { get; set; }
    public string param1 { get; set; }
}

public class Winlog
{
    public string channel { get; set; }
    public string event_id { get; set; }
    public string api { get; set; }
    public int record_id { get; set; }
    public string computer_name { get; set; }
    public string provider_name { get; set; }
    public string provider_guid { get; set; }
    public List<string> keywords { get; set; }
    public EventData event_data { get; set; }
}

public class Event
{
    public string kind { get; set; }
    public string provider { get; set; }
    public string created { get; set; }
    public string code { get; set; }
}

public class Log
{
    public string level { get; set; }
}

public class WinlogBeat
{
    [JsonProperty("@timestamp")] public DateTime? Timestamp { get; set; }

    [JsonProperty("@metadata")] public Metadata Metadata { get; set; }
    public string message { get; set; }
    public Ecs ecs { get; set; }
    public Agent agent { get; set; }
    public Host host { get; set; }
    public Process? process { get; set; }
    public Winlog winlog { get; set; }
    public Event @event { get; set; }
    public Log log { get; set; }
    public string verdict { get; set; } = "Benign";
    public bool isMalicious { get; set; } = false;

    /// <summary>
    /// > If the timestamp of the current object is between the delegated and finished timestamps of the
    /// maliciousPid object, then return true
    /// </summary>
    /// <param name="MaliciousPid">This is a class that contains the following properties:</param>
    /// <returns>
    /// A boolean value.
    /// </returns>
    public bool IsWithinMaliciousOperationTimePeriod(MaliciousPid maliciousPid)
    {
        return maliciousPid.finished_timestamp != null && maliciousPid.delegated_timestamp != null && Timestamp != null &&
               Timestamp.Value.TrimMilliseconds() >= maliciousPid.delegated_timestamp.Value.TrimMilliseconds() &&
               Timestamp.Value.TrimMilliseconds() <= maliciousPid.finished_timestamp.Value.TrimMilliseconds();
    }

    /// <summary>
    /// If the process ID of the current process matches the malicious process ID, and the current process
    /// is not malicious, or if the process ID of the parent process of the current process matches the
    /// malicious process ID, and the current process is not malicious, then return true
    /// </summary>
    /// <param name="MaliciousPid">A class that contains a pid and a name.</param>
    public bool MatchesMaliciousPid(MaliciousPid maliciousPid)
    {
        return process?.pid == maliciousPid.pid && !isMalicious ||
               process?.parent?.pid == maliciousPid.pid && !isMalicious;
    }
    
}

public class MaliciousPid
{
    public MaliciousPid(int? pid, string techniqueId, string techniqueName, DateTime? delegatedTimestamp,
        DateTime? finishedTimestamp, AgentMetadata agentMetadata, AttackMetadata attackMetadata)
    {
        this.pid = pid;
        technique_id = techniqueId;
        technique_name = techniqueName;
        delegated_timestamp = delegatedTimestamp;
        this.finished_timestamp = finishedTimestamp;
        this.agentMetadata = agentMetadata;
        this.attackMetadata = attackMetadata;
    }

    public int? pid { get; set; }
    public string technique_id { get; set; }
    public string technique_name { get; set; }
    public DateTime? delegated_timestamp { get; set; }
    public DateTime? finished_timestamp { get; set; }
    public AgentMetadata agentMetadata { get; set; }
    public AttackMetadata attackMetadata { get; set; }

}
