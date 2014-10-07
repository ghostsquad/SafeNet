using System.IO;
using System.Security.AccessControl;
using System.Text;

namespace SafeNet.Core.Wrappers {
    public class WindowsEnvironment : EnvironmentWrapper {
        public override DirectoryInfo CreateDirectory(string path) {
            return Directory.CreateDirectory(path);
        }

        public override void WriteAllText(string path, string contents) {
            File.WriteAllText(path, contents);
        }

        public override void WriteAllText(string path, string contents, Encoding encoding) {
            File.WriteAllText(path, contents, encoding);
        }

        public override bool DirectoryExists(string path) {
            return Directory.Exists(path);
        }

        public override void SetAccessControl(FileSystemInfo fileSystemInfo, FileSystemSecurity fileSystemSecurity) {
            var dirInfo = fileSystemInfo as DirectoryInfo;
            if (dirInfo != null) {
                dirInfo.SetAccessControl((DirectorySecurity)fileSystemSecurity);
            } else {
                ((FileInfo)fileSystemInfo).SetAccessControl((FileSecurity)fileSystemSecurity);
            }
        }
    }
}