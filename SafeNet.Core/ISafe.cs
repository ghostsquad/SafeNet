namespace SafeNet.Core {
    using System.Collections.Generic;

    public interface ISafe {

	    void UpsertSecret(ISecret secret);

        ISecret RetrieveSecret(string target);

        void StoreSecret(ISecret secret);

        IList<ISecret> SearchSecrets(string pattern, SafeSearchMethod method);

        IList<ISecret> Secrets { get; }
    }
}
