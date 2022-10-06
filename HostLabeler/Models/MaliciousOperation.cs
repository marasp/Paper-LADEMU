using System;

namespace loglabel.Models
{
    public class AgentMetadata
    {
        public string paw { get; set; }
        public string group { get; set; }
        public string architecture { get; set; }
        public string username { get; set; }
        public string location { get; set; }
        public int? pid { get; set; }
        public int? ppid { get; set; }
        public string privilege { get; set; }
        public string host { get; set; }
        public string contact { get; set; }
        public DateTime created { get; set; }
    }

    public class AbilityMetadata
    {
        public string ability_id { get; set; }
        public string ability_name { get; set; }
        public string ability_description { get; set; }
    }

    public class OperationMetadata
    {
        public string operation_name { get; set; }
        public string operation_start { get; set; }
        public string operation_adversary { get; set; }
    }

    public class AttackMetadata
    {
        public string tactic { get; set; }
        public string technique_name { get; set; }
        public string technique_id { get; set; }
    }

    public class MaliciousOperation
    {
        public string command { get; set; }
        public DateTime? delegated_timestamp { get; set; }
        public DateTime? collected_timestamp { get; set; }
        public DateTime? finished_timestamp { get; set; }
        public int status { get; set; }
        public string platform { get; set; }
        public string executor { get; set; }
        public int? pid { get; set; }
        public AgentMetadata agent_metadata { get; set; }
        public AbilityMetadata ability_metadata { get; set; }
        public OperationMetadata operation_metadata { get; set; }
        public AttackMetadata attack_metadata { get; set; }
        public string agent_reported_time { get; set; }
    }
}