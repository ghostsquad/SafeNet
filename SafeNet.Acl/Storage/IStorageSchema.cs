namespace SafeNet.Acl.Storage {
    using System.Collections.Generic;
    using System.IO;

    using SafeNet.Core;

    public interface IStorageSchema {

        FileSystemInfo SafeObjectInfo { get; }

        void WriteSecret(ISecret secret);

        IList<ISecret> GetSecrets();
    }
}
