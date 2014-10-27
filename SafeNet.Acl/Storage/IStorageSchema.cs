using System.Collections;
using System.Collections.Generic;

namespace SafeNet.Acl.Storage {
    using System.IO;

    using SafeNet.Core;

    public interface IStorageSchema {

        FileSystemInfo SafeObjectInfo { get; }

        ISecret ReadSecret(string searchPattern, SafeSearchMethod method);

        void WriteSecret(ISecret secret);

        IList<ISecret> GetSecrets();
    }
}
