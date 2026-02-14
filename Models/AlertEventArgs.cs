using System;

namespace CommandAndControll.Models
{
    public class AlertEventArgs : EventArgs
    {
        public MonitoredProcess Process { get; set; }
        public string Message { get; set; }
    }
}