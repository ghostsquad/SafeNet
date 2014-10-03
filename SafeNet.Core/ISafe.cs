namespace SafeNet.Core {
    using System.Collections.Generic;

    public interface ISafe {

        bool RetrieveSecret(string target, out ISecret secret);

        bool StoreSecret(ISecret secret);

        IList<ISecret> SearchSecrets(string pattern, SafeSearchOptions options);
    }
}
