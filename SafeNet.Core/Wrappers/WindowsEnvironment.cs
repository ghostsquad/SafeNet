// --------------------------------------------------------------------------------------------------------------------
// <copyright file="WindowsEnvironment.cs" company="">
//   
// </copyright>
// <summary>
//   The windows environment.
// </summary>
// --------------------------------------------------------------------------------------------------------------------
namespace SafeNet.Core.Wrappers {
    using System.IO;
    using System.Security.AccessControl;

    /// <summary>
    /// The windows environment.
    /// </summary>
    public class WindowsEnvironment : EnvironmentWrapper {
        #region Static Fields

        /// <summary>
        /// The instance.
        /// </summary>
        private static WindowsEnvironment instance;

        #endregion

        #region Constructors and Destructors

        /// <summary>
        /// Prevents a default instance of the <see cref="WindowsEnvironment"/> class from being created.
        /// </summary>
        private WindowsEnvironment() {
        }

        #endregion

        #region Public Properties

        /// <summary>
        /// Gets the default.
        /// </summary>
        public static WindowsEnvironment Default {
            get {
                if (instance == null) {
                    instance = new WindowsEnvironment();
                }

                return instance;
            }
        }

        #endregion

        #region Public Methods and Operators

        /// <summary>
        /// The create directory.
        /// </summary>
        /// <param name="path">
        /// The path.
        /// </param>
        /// <returns>
        /// The <see cref="DirectoryInfo"/>.
        /// </returns>
        public override DirectoryInfo CreateDirectory(string path) {
            return Directory.CreateDirectory(path);
        }

        /// <summary>
        /// The directory exists.
        /// </summary>
        /// <param name="path">
        /// The path.
        /// </param>
        /// <returns>
        /// The <see cref="bool"/>.
        /// </returns>
        public override bool DirectoryExists(string path) {
            return Directory.Exists(path);
        }

        /// <summary>
        /// The file exists.
        /// </summary>
        /// <param name="path">
        /// The path.
        /// </param>
        /// <returns>
        /// The <see cref="bool"/>.
        /// </returns>
        public override bool FileExists(string path) {
            return File.Exists(path);
        }

        /// <summary>
        /// The read all text.
        /// </summary>
        /// <param name="path">
        /// The path.
        /// </param>
        /// <returns>
        /// The <see cref="string"/>.
        /// </returns>
        public override string ReadAllText(string path) {
            return File.ReadAllText(path);
        }

        /// <summary>
        /// The set access control.
        /// </summary>
        /// <param name="fileInfo">
        /// The file info.
        /// </param>
        /// <param name="fileSystemSecurity">
        /// The file system security.
        /// </param>
        public override void SetAccessControl(FileInfo fileInfo, FileSystemSecurity fileSystemSecurity) {
            fileInfo.SetAccessControl((FileSecurity)fileSystemSecurity);
        }

        /// <summary>
        /// The set access control.
        /// </summary>
        /// <param name="directoryInfo">
        /// The directory info.
        /// </param>
        /// <param name="fileSystemSecurity">
        /// The file system security.
        /// </param>
        public override void SetAccessControl(DirectoryInfo directoryInfo, FileSystemSecurity fileSystemSecurity) {
            directoryInfo.SetAccessControl((DirectorySecurity)fileSystemSecurity);
        }

        /// <summary>
        /// The write all text.
        /// </summary>
        /// <param name="path">
        /// The path.
        /// </param>
        /// <param name="contents">
        /// The contents.
        /// </param>
        public override void WriteAllText(string path, string contents) {
            File.WriteAllText(path, contents);
        }

        #endregion
    }
}