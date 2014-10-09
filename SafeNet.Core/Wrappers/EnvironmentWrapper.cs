using System.Text;

namespace SafeNet.Core {
    using System.Collections.Generic;
    using System.IO;
    using System.Security.AccessControl;

    public abstract class EnvironmentWrapper {
        public abstract DirectoryInfo CreateDirectory(string path);

        public abstract void WriteAllText(string path, string contents);

        public abstract string ReadAllText(string path);

        public abstract bool DirectoryExists(string path);

        public abstract bool FileExists(string path);

        public abstract void SetAccessControl(FileInfo fileInfo, FileSystemSecurity fileSystemSecurity);

        public abstract void SetAccessControl(DirectoryInfo directoryInfo, FileSystemSecurity fileSystemSecurity);
    }
}
