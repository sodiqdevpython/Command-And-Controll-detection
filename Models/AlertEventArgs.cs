using System;

namespace CommandAndControl.Models
{
    public class AlertEventArgs : EventArgs
    {
        public MonitoredProcess Process { get; set; }
        public string Message { get; set; }
    }
}