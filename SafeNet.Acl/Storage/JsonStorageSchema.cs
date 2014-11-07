namespace SafeNet.Acl.Storage {
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;

    using Newtonsoft.Json;
    using Newtonsoft.Json.Linq;

    using SafeNet.Core;

    public class JsonStorageSchema : IStorageSchema {
        private readonly EnvironmentWrapper environment;

        public JsonStorageSchema(EnvironmentWrapper environment)
            : this(null, environment) {
        }

        public JsonStorageSchema(FileInfo safeFile, EnvironmentWrapper environment) {
            this.SafeFile = safeFile;
            this.environment = environment;
        }

        public FileInfo SafeFile { get; set; }

        public FileSystemInfo SafeObjectInfo
        {
            get
            {
                return this.SafeFile;
            }
            set
            {
                this.SafeFile = value as FileInfo;
            }
        }

        public void WriteSecret(ISecret secret) {
            if (this.SafeFile == null) {
                throw new InvalidOperationException("SafeFile has not been set.");
            }

            var secrets = this.GetSecrets().ToList();
            var secretIndex = secrets.FindIndex(x => x.Equals(secret));
            if (secretIndex >= 0) {
                secrets.RemoveAt(secretIndex);
                secrets.Insert(secretIndex, secret);
            }
            else {
                secrets.Add(secret);
            }

            this.environment.WriteAllText(
                this.SafeFile.FullName,
                JsonConvert.SerializeObject(secrets, Formatting.Indented));
        }

        public IList<ISecret> GetSecrets() {
            if (this.SafeFile == null) {
                throw new InvalidOperationException("SafeFile has not been set.");
            }

            var safeContents = this.environment.ReadAllText(this.SafeFile.FullName);
            if (string.IsNullOrWhiteSpace(safeContents)) {
                safeContents = "[]";
            }

            return new List<ISecret>(JArray.Parse(safeContents).ToObject<IList<Secret>>());
        }
    }
}