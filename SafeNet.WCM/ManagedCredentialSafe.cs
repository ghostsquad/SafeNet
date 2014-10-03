namespace SafeNet.Wcm
{
    using System;
    using System.Collections.Generic;

    using SafeNet.Core;

    public class ManagedCredentialSafe : ISafe
    {
        public bool RetrieveSecret(string target, out ISecret secret) {
            throw new NotImplementedException();
        }

        public bool StoreSecret(ISecret secret) {
            throw new NotImplementedException();
        }

        public IList<ISecret> SearchSecrets(string pattern, SafeSearchOptions options) {
            throw new NotImplementedException();
        }
    }
}
