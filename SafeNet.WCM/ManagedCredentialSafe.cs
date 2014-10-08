namespace SafeNet.Wcm
{
    using System;
    using System.Collections.Generic;

    using SafeNet.Core;

    public class ManagedCredentialSafe : ISafe
    {
        public ISecret RetrieveSecret(string target) {
            throw new NotImplementedException();
        }

        public bool StoreSecret(ISecret secret) {
            throw new NotImplementedException();
        }

        public IList<ISecret> SearchSecrets(string pattern, SafeSearchMethod method) {
            throw new NotImplementedException();
        }
    }
}
