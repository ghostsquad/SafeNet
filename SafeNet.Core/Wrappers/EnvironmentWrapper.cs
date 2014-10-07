using System.Text;

namespace SafeNet.Core {
    using System.IO;
    using System.Security.AccessControl;

    public abstract class EnvironmentWrapper {
        public abstract DirectoryInfo CreateDirectory(string path);

        public abstract void WriteAllText(string path, string contents);

        public abstract void WriteAllText(string path, string contents, Encoding encoding);

        public abstract bool DirectoryExists(string path);

        public abstract void SetAccessControl(FileSystemInfo fileSystemInfo, FileSystemSecurity fileSystemSecurity);
    }
}
