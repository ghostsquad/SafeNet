namespace SafeNet.Acl.Storage {
    using System.IO;

    using SafeNet.Core;

    public interface IStorageSchema {

        ISecret ReadSecret(FileInfo safeFile, string searchPattern, SafeSearchMethod method);

        void WriteSecret(FileInfo safeFile, ISecret secret);
    }
}
