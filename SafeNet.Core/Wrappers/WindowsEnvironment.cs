namespace SafeNet.Core.Wrappers {
    using System.IO;
    using System.Security.AccessControl;
    using System.Text;

    public class WindowsEnvironment : EnvironmentWrapper {
        public override DirectoryInfo CreateDirectory(string path) {
            return Directory.CreateDirectory(path);
        }

        public override void WriteAllText(string path, string contents) {
            File.WriteAllText(path, contents);
        }

        public override bool DirectoryExists(string path) {
            return Directory.Exists(path);
        }

        public override bool FileExists(string path) {
            return File.Exists(path);
        }

        public override void SetAccessControl(FileInfo fileInfo, FileSystemSecurity fileSystemSecurity) {
            fileInfo.SetAccessControl((FileSecurity)fileSystemSecurity);
        }

        public override void SetAccessControl(DirectoryInfo directoryInfo, FileSystemSecurity fileSystemSecurity) {
            directoryInfo.SetAccessControl((DirectorySecurity)fileSystemSecurity);
        }
    }
}