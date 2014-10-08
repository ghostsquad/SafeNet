namespace SafeNet.Acl.Test {
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;

    using FluentAssertions;

    using Moq;

    using SafeNet.Acl.Storage;
    using SafeNet.Core;
    using SafeNet.Test.Common;

    using Xunit;

    public class JsonStorageSchemaTests {

        private readonly FileInfo secretsVaultFile;

        private readonly Testable<JsonStorageSchema> testable;

        private readonly Mock<EnvironmentWrapper> environmentMock;

        private const string ExpectedTarget = "Hello World";

        public JsonStorageSchemaTests() {
            this.secretsVaultFile =
                new FileInfo(Path.Combine(Environment.CurrentDirectory, "TestData", "SecretsVault.json"));

            this.testable = new Testable<JsonStorageSchema>();
            this.testable.InjectMock<EnvironmentWrapper>();
        }

        [Fact]
        public void ReadSecret_WithWildCardSearch() {
            const string SearchPattern = "Hello*";

            var actualSecret = this.testable.ClassUnderTest.ReadSecret(
                this.secretsVaultFile,
                SearchPattern,
                SafeSearchMethod.Wildcard);

            actualSecret.Should().NotBeNull();
            actualSecret.Target.Should().Be(ExpectedTarget);
        }

        [Fact]
        public void ReadSecret_WithWildCardSearch_WhenNoMatch_ExpectNull() {
            const string BadPattern = "Foo*";

            var actualSecret = this.testable.ClassUnderTest.ReadSecret(
                this.secretsVaultFile,
                BadPattern,
                SafeSearchMethod.Wildcard);

            actualSecret.Should().BeNull();
        }

        [Fact]
        public void ReadSecret_WithRegexCardSearch() {
            const string SearchPattern = @"^Hello \w+";

            var actualSecret = this.testable.ClassUnderTest.ReadSecret(
                this.secretsVaultFile,
                SearchPattern,
                SafeSearchMethod.Regex);

            actualSecret.Should().NotBeNull();
            actualSecret.Target.Should().Be(ExpectedTarget);
        }

        [Fact]
        public void ReadSecret_WithRegexSearch_WhenNoMatch_ExpectNull() {
            const string BadPattern = "Foo.*";

            var actualSecret = this.testable.ClassUnderTest.ReadSecret(
                this.secretsVaultFile,
                BadPattern,
                SafeSearchMethod.Regex);

            actualSecret.Should().BeNull();
        }

        [Fact]
        public void ReadSecret_WithNoneSearchMethod() {
            var actualSecret = this.testable.ClassUnderTest.ReadSecret(
                this.secretsVaultFile,
                ExpectedTarget,
                SafeSearchMethod.None);
        }

        [Fact]
        public void ReadSecret_WithNoneSearchMethod_WhenNoMatch_ExpectNull() {
            const string BadPattern = "Foo";

            var actualSecret = this.testable.ClassUnderTest.ReadSecret(
                this.secretsVaultFile,
                BadPattern,
                SafeSearchMethod.None);

            actualSecret.Should().BeNull();
        }
    }
}
