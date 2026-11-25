using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

[assembly: DefaultDllImportSearchPaths(DllImportSearchPath.System32)]

namespace LinkScope {
    // Use the SQLite engine shipped with Windows. Paths, SQL and parameters use UTF-8.
    internal sealed class Sqlite : IDisposable {
        const string Lib = "winsqlite3.dll";
        internal const CallingConvention CC = CallingConvention.Cdecl;
        [DllImport(Lib, CallingConvention=CC)] static extern int sqlite3_open_v2(byte[] name, out IntPtr db, int flags, IntPtr vfs);
        [DllImport(Lib, CallingConvention=CC)] static extern int sqlite3_close(IntPtr db);
        [DllImport(Lib, CallingConvention=CC)] static extern IntPtr sqlite3_errmsg(IntPtr db);
        [DllImport(Lib, CallingConvention=CC)] static extern int sqlite3_busy_timeout(IntPtr db, int ms);
        [DllImport(Lib, CallingConvention=CC)] static extern int sqlite3_prepare_v2(IntPtr db, byte[] sql, int size, out IntPtr stmt, IntPtr tail);
        [DllImport(Lib, CallingConvention=CC)] static extern int sqlite3_finalize(IntPtr stmt);
        [DllImport(Lib, CallingConvention=CC)] static extern int sqlite3_step(IntPtr stmt);
        [DllImport(Lib, CallingConvention=CC)] static extern int sqlite3_reset(IntPtr stmt);
        [DllImport(Lib, CallingConvention=CC)] static extern int sqlite3_bind_int64(IntPtr stmt, int index, long val);
        [DllImport(Lib, CallingConvention=CC)] static extern int sqlite3_bind_double(IntPtr stmt, int index, double val);
        [DllImport(Lib, CallingConvention=CC)] static extern int sqlite3_bind_null(IntPtr stmt, int index);
        [DllImport(Lib, CallingConvention=CC)] static extern int sqlite3_bind_text(IntPtr stmt, int index, byte[] val, int length, IntPtr free);
        [DllImport(Lib, CallingConvention=CC)] static extern int sqlite3_column_count(IntPtr stmt);
        [DllImport(Lib, CallingConvention=CC)] static extern int sqlite3_column_type(IntPtr stmt, int col);
        [DllImport(Lib, CallingConvention=CC)] static extern long sqlite3_column_int64(IntPtr stmt, int col);
        [DllImport(Lib, CallingConvention=CC)] static extern double sqlite3_column_double(IntPtr stmt, int col);
        [DllImport(Lib, CallingConvention=CC)] static extern IntPtr sqlite3_column_text(IntPtr stmt, int col);
        [DllImport(Lib, CallingConvention=CC)] static extern int sqlite3_column_bytes(IntPtr stmt, int col);

        IntPtr handle;
        readonly Dictionary<string,IntPtr> cache = new Dictionary<string,IntPtr>();
        static byte[] Utf8(string s) { return Encoding.UTF8.GetBytes(s + "\0"); }
        static string ReadText(IntPtr ptr, int n) {
            if (ptr == IntPtr.Zero || n == 0) return "";
            byte[] b = new byte[n];
            Marshal.Copy(ptr, b, 0, n);
            return Encoding.UTF8.GetString(b);
        }
        public Sqlite(bool readOnly) : this(Config.Db,readOnly) {}
        internal Sqlite(string filename,bool readOnly) {
            int rc = sqlite3_open_v2(Utf8(filename), out handle, readOnly ? 1 : 6, IntPtr.Zero);
            try {
                Check(rc);
                Check(sqlite3_busy_timeout(handle, 5000));
            } catch { Dispose(); throw; }
        }
        void Check(int rc) {
            if (rc == 0) return;
            string message = handle == IntPtr.Zero ? "open failed" : Marshal.PtrToStringAnsi(sqlite3_errmsg(handle));
            throw new InvalidOperationException("SQLite " + rc + ": " + message);
        }
        IntPtr Bind(string sql, object[] values) {
            IntPtr stmt;
            if (!cache.TryGetValue(sql, out stmt)) {
                Check(sqlite3_prepare_v2(handle, Utf8(sql), -1, out stmt, IntPtr.Zero));
                cache.Add(sql, stmt);
            }
            for (int i=0; i<values.Length; i++) {
                object v = values[i];
                if (v == null) Check(sqlite3_bind_null(stmt, i+1));
                else if (v is string) Check(sqlite3_bind_text(stmt, i+1, Utf8((string)v), -1, new IntPtr(-1)));
                else if (v is double) Check(sqlite3_bind_double(stmt, i+1, (double)v));
                else Check(sqlite3_bind_int64(stmt, i+1, Convert.ToInt64(v)));
            }
            return stmt;
        }
        public void Exec(string sql, params object[] values) {
            IntPtr s = Bind(sql, values);
            try {
                int rc;
                do { rc = sqlite3_step(s); } while (rc == 100);
                if (rc != 101) Check(rc);
            } finally { sqlite3_reset(s); }
        }
        public List<object[]> Rows(string sql, params object[] values) {
            IntPtr s = Bind(sql, values);
            var rows = new List<object[]>();
            try {
                int rc;
                while ((rc = sqlite3_step(s)) == 100) {
                    object[] row = new object[sqlite3_column_count(s)];
                    for (int i=0; i<row.Length; i++) {
                        switch (sqlite3_column_type(s,i)) {
                            case 1: row[i] = sqlite3_column_int64(s,i); break;
                            case 2: row[i] = sqlite3_column_double(s,i); break;
                            case 3: row[i] = ReadText(sqlite3_column_text(s,i), sqlite3_column_bytes(s,i)); break;
                        }
                    }
                    rows.Add(row);
                }
                if (rc != 101) Check(rc);
                return rows;
            } finally { sqlite3_reset(s); }
        }
        public void Dispose() {
            foreach (IntPtr s in cache.Values) sqlite3_finalize(s);
            cache.Clear();
            if (handle != IntPtr.Zero) sqlite3_close(handle);
            handle = IntPtr.Zero;
        }
    }
}
