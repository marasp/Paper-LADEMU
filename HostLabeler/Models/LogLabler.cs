using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using loglabel.Extensions;
using Newtonsoft.Json;

namespace loglabel.Models
{
    public class LogLabeler
    {
        public LogLabeler(List<WinlogBeat> winlogBeats, IEnumerable<MaliciousOperation> maliciousOperations)
        {
            this.winLogBeats = winlogBeats;
            var operations = maliciousOperations.Select(x => new MaliciousPid(x.pid, x.attack_metadata.technique_id,
                x.attack_metadata.technique_name, x.delegated_timestamp, x.finished_timestamp, x.agent_metadata, x.attack_metadata)).ToList();

            operations.AddRange(maliciousOperations.Select(x => new MaliciousPid(x.agent_metadata.pid,
                x.attack_metadata.technique_id, x.attack_metadata.technique_name, x.delegated_timestamp, x.finished_timestamp,
                x.agent_metadata, x.attack_metadata)).ToList());

            operations.AddRange(maliciousOperations.Select(x => new MaliciousPid(x.agent_metadata.ppid,
                x.attack_metadata.technique_id, x.attack_metadata.technique_name, x.delegated_timestamp, x.finished_timestamp,
                x.agent_metadata, x.attack_metadata)).ToList());

            this.maliciousPids = operations.Distinct().ToList();
        }
        
        private List<WinlogBeat> winLogBeats { get; set; }
        private List<MaliciousPid> maliciousPids { get; set; }

        public int maliciousOperationsIdentified { get; set; } = 0;
        
        /// <summary>
        /// For each malicious process id, find all winlogbeat events that match the malicious process id, and
        /// mark them as malicious. Then, find all the child processes of the malicious process id, and repeat
        /// the process
        /// </summary>
        /// <param name="pids">List of malicious pids from CALDERA</param>
        public LogLabeler FindAndMarkAllDescendantMaliciousOperations()
        {
            var newMaliciousPids = new List<MaliciousPid>();
            foreach (var pid in this.maliciousPids) //CALDERA
            {
                if (pid.pid == null) continue;
                foreach (var winlogBeat in winLogBeats) //WINLOGBEAT
                {
                    if (!winlogBeat.MatchesMaliciousPid(pid)) continue;
                    if (winlogBeat.IsWithinMaliciousOperationTimePeriod(pid))
                    {
                        winlogBeat.isMalicious = true;
                        winlogBeat.verdict = "Malicious " + pid.attackMetadata.tactic + " - " + pid.technique_name + " - " + pid.technique_id;
                        this.maliciousOperationsIdentified += 1;
                    }
                    else
                    {
                        if (winlogBeat.winlog.event_id == "3")
                        {
                            winlogBeat.isMalicious = true;
                            this.maliciousOperationsIdentified += 1;
                            winlogBeat.verdict = "Malicious, command and control traffic";
                        }
                        else if (winlogBeat.Timestamp != null && winlogBeat.Timestamp.Value.TrimMilliseconds() >=
                            maliciousPids.Select(x => x.agentMetadata.created).Min().TrimMilliseconds())
                        {
                            winlogBeat.verdict = "Background, seen in relation to " + pid.attackMetadata.tactic + " - " + pid.technique_name + " - " + pid.technique_id;
                            continue;
                        }
                    }

                    newMaliciousPids.Add(new MaliciousPid(winlogBeat?.process?.pid, pid.technique_id, pid.technique_name,
                        pid.delegated_timestamp, pid.finished_timestamp, pid.agentMetadata, pid.attackMetadata));
                    newMaliciousPids.Add(new MaliciousPid(winlogBeat?.process?.parent?.pid, pid.technique_id, pid.technique_name,
                        pid.delegated_timestamp, pid.finished_timestamp, pid.agentMetadata, pid.attackMetadata));
                }
            }

            this.maliciousPids = newMaliciousPids.Distinct().ToList();
            if (maliciousPids.Count > 0) FindAndMarkAllDescendantMaliciousOperations();
            return this;
        }
        
        /// <summary>
        /// It takes in a JSON object, and writes it to a file
        /// </summary>
        /// <param name="data">the data you want to save to a file</param>
        public LogLabeler SaveJsonToFile(string path)
        {
            using StreamWriter file =
                File.CreateText(path);
            JsonSerializer serializer = new JsonSerializer();

            serializer.Serialize(file, winLogBeats);
            return this;
        }
        
        public LogLabeler PrintMaliciousOperationsIdentified()
        {
            Console.WriteLine("Number of malicious operations identified: " + maliciousOperationsIdentified);
            return this;
        }
    }
}