// Real-time kernel ETW consumer for the EDR canary.
//
// TraceEvent dispatches callbacks on the thread that calls Source.Process(). Running that
// loop on a dedicated background thread and handing events to PowerShell through a bounded
// BlockingCollection avoids invoking PowerShell script blocks from a foreign thread (which
// has no runspace) and gives explicit back-pressure: when the analysis loop falls behind,
// events are counted as dropped instead of growing memory without limit.
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Threading;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Parsers.Kernel;
using Microsoft.Diagnostics.Tracing.Session;

namespace EdrCanary
{
    /// <summary>
    /// Reads process (and optionally file and disk I/O) events from the kernel ETW provider
    /// on a background thread and queues them for PowerShell to consume with <see cref="Take"/>.
    /// </summary>
    public sealed class EtwKernelConsumer : IDisposable
    {
        private readonly BlockingCollection<Dictionary<string, object>> _events;
        private TraceEventSession _session;
        private Thread _thread;
        private long _dropped;
        private long _received;

        /// <summary>Creates a consumer whose queue holds at most <paramref name="capacity"/> events.</summary>
        public EtwKernelConsumer(int capacity)
        {
            _events = new BlockingCollection<Dictionary<string, object>>(capacity);
        }

        /// <summary>Events discarded because the queue was full.</summary>
        public long Dropped { get { return Interlocked.Read(ref _dropped); } }
        /// <summary>Events received from ETW, including dropped ones.</summary>
        public long Received { get { return Interlocked.Read(ref _received); } }
        /// <summary>True while the ETW processing thread is alive.</summary>
        public bool IsRunning { get { return _thread != null && _thread.IsAlive; } }
        /// <summary>The exception that stopped the processing thread, if any.</summary>
        public string LastError { get; private set; }

        /// <summary>True when the process runs elevated, which kernel ETW sessions require.</summary>
        public static bool IsElevated()
        {
            return TraceEventSession.IsElevated() == true;
        }

        /// <summary>
        /// Starts the NT Kernel Logger session and the processing thread.
        /// </summary>
        /// <param name="includeFileIo">Also capture file create, write, rename and delete events.</param>
        /// <param name="includeDiskIo">Also capture physical disk writes.</param>
        /// <exception cref="InvalidOperationException">The consumer was already started.</exception>
        public void Start(bool includeFileIo, bool includeDiskIo)
        {
            if (_session != null) throw new InvalidOperationException("consumer already started");
            // Kernel providers require the NT Kernel Logger session on Windows 7 and remain the
            // most compatible choice; StopOnDispose guarantees we never leak a kernel session.
            _session = new TraceEventSession(KernelTraceEventParser.KernelSessionName);
            _session.StopOnDispose = true;

            var keywords = KernelTraceEventParser.Keywords.Process;
            if (includeFileIo)
                keywords |= KernelTraceEventParser.Keywords.FileIOInit | KernelTraceEventParser.Keywords.FileIO;
            if (includeDiskIo)
                keywords |= KernelTraceEventParser.Keywords.DiskIO | KernelTraceEventParser.Keywords.DiskFileIO;
            _session.EnableKernelProvider(keywords);

            var kernel = _session.Source.Kernel;
            kernel.ProcessStart += d => Push(new Dictionary<string, object> {
                { "Type", "ProcessStart" }, { "TimeStamp", d.TimeStamp.ToUniversalTime() },
                { "ProcessId", d.ProcessID }, { "ParentProcessId", d.ParentID },
                { "ImageName", d.ImageFileName }, { "CommandLine", d.CommandLine } });
            kernel.ProcessStop += d => Push(new Dictionary<string, object> {
                { "Type", "ProcessStop" }, { "TimeStamp", d.TimeStamp.ToUniversalTime() },
                { "ProcessId", d.ProcessID }, { "ImageName", d.ImageFileName } });
            if (includeFileIo)
            {
                kernel.FileIOCreate += d => Push(FileEvent("FileCreate", d.TimeStamp, d.ProcessID, d.FileName, 0));
                kernel.FileIOWrite += d => Push(FileEvent("FileWrite", d.TimeStamp, d.ProcessID, d.FileName, d.IoSize));
                kernel.FileIORename += d => Push(FileEvent("FileRename", d.TimeStamp, d.ProcessID, d.FileName, 0));
                kernel.FileIODelete += d => Push(FileEvent("FileDelete", d.TimeStamp, d.ProcessID, d.FileName, 0));
            }
            if (includeDiskIo)
            {
                kernel.DiskIOWrite += d => Push(FileEvent("DiskWrite", d.TimeStamp, d.ProcessID, d.FileName, d.TransferSize));
            }

            _thread = new Thread(() =>
            {
                try { _session.Source.Process(); }
                catch (Exception ex) { LastError = ex.GetType().Name + ": " + ex.Message; }
                finally { _events.CompleteAdding(); }
            });
            _thread.IsBackground = true;
            _thread.Name = "EdrCanary-ETW";
            _thread.Start();
        }

        // Builds the canonical file-event dictionary shared by every file and disk callback.
        private static Dictionary<string, object> FileEvent(string type, DateTime ts, int pid, string path, long size)
        {
            return new Dictionary<string, object> {
                { "Type", type }, { "TimeStamp", ts.ToUniversalTime() }, { "ProcessId", pid },
                { "FilePath", path ?? string.Empty }, { "Size", size } };
        }

        // Enqueues without blocking the ETW thread; a full queue counts the event as dropped.
        private void Push(Dictionary<string, object> evt)
        {
            Interlocked.Increment(ref _received);
            if (!_events.TryAdd(evt)) Interlocked.Increment(ref _dropped);
        }

        /// <summary>Waits up to <paramref name="timeoutMs"/> for the next event.</summary>
        /// <returns>The event, or null on timeout or once the session has ended.</returns>
        public Dictionary<string, object> Take(int timeoutMs)
        {
            Dictionary<string, object> evt;
            return _events.TryTake(out evt, timeoutMs) ? evt : null;
        }

        /// <summary>True once the session has ended and every queued event has been taken.</summary>
        public bool IsCompleted { get { return _events.IsCompleted; } }

        /// <summary>Stops the kernel session and waits up to 5 seconds for the processing thread.</summary>
        public void Dispose()
        {
            if (_session != null) { _session.Dispose(); _session = null; }
            if (_thread != null) { _thread.Join(5000); _thread = null; }
        }
    }
}
