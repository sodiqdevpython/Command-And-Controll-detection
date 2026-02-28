using System;

namespace CommandAndControl.Models
{
    public class TrafficEventArgs : EventArgs
    {
        public int Pid { get; set; }
        public float CurrentScore { get; set; }
        public bool IsSend { get; set; }
        public string RemoteAddress { get; set; }
        public int RemotePort { get; set; }
        public int Size { get; set; }
        public string ProcessPath { get; set; }
    }
}