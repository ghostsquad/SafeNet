namespace SafeNet.Core {
    using System.Collections.Generic;

    public interface ISafe {

        ISecret RetrieveSecret(string target);

        bool StoreSecret(ISecret secret);

        IList<ISecret> SearchSecrets(string pattern, SafeSearchMethod method);
    }
}
