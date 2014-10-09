namespace SafeNet.Acl.Test {
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;

    using FluentAssertions;

    using Moq;

    using Newtonsoft.Json;
    using Newtonsoft.Json.Linq;

    using Ploeh.AutoFixture;

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
            this.environmentMock = this.testable.InjectMock<EnvironmentWrapper>();
            this.environmentMock.Setup(x => x.ReadAllText(It.IsAny<string>()))
                .Returns(File.ReadAllText(this.secretsVaultFile.FullName));
            this.testable.Fixture.Register(() => this.secretsVaultFile);
        }

        [Fact]
        public void ReadSecret_WithWildCardSearch() {
            const string SearchPattern = "Hello*";

            var actualSecret = this.testable.ClassUnderTest.ReadSecret(
                SearchPattern,
                SafeSearchMethod.Wildcard);

            actualSecret.Should().NotBeNull();
            actualSecret.Target.Should().Be(ExpectedTarget);
        }

        [Fact]
        public void ReadSecret_WithWildCardSearch_WhenNoMatch_ExpectNull() {
            const string BadPattern = "Foo*";

            var actualSecret = this.testable.ClassUnderTest.ReadSecret(
                BadPattern,
                SafeSearchMethod.Wildcard);

            actualSecret.Should().BeNull();
        }

        [Fact]
        public void ReadSecret_WithRegexCardSearch() {
            const string SearchPattern = @"^Hello \w+";

            var actualSecret = this.testable.ClassUnderTest.ReadSecret(
                SearchPattern,
                SafeSearchMethod.Regex);

            actualSecret.Should().NotBeNull();
            actualSecret.Target.Should().Be(ExpectedTarget);
        }

        [Fact]
        public void ReadSecret_WithRegexSearch_WhenNoMatch_ExpectNull() {
            const string BadPattern = "Foo.*";

            var actualSecret = this.testable.ClassUnderTest.ReadSecret(
                BadPattern,
                SafeSearchMethod.Regex);

            actualSecret.Should().BeNull();
        }

        [Fact]
        public void ReadSecret_WithNoneSearchMethod() {
            var actualSecret = this.testable.ClassUnderTest.ReadSecret(
                ExpectedTarget,
                SafeSearchMethod.None);

            actualSecret.Should().NotBeNull();
            actualSecret.Target.Should().Be(ExpectedTarget);
        }

        [Fact]
        public void ReadSecret_WithNoneSearchMethod_WhenNoMatch_ExpectNull() {
            const string BadPattern = "Foo";

            var actualSecret = this.testable.ClassUnderTest.ReadSecret(
                BadPattern,
                SafeSearchMethod.None);

            actualSecret.Should().BeNull();
        }

        [Fact]
        public void WriteSecret_GivenEmptySecretsFile_ExpectNewList() {
            var fixture = new Fixture();
            var expectedSecret = fixture.Create<Secret>();
            this.environmentMock.Setup(x => x.ReadAllText(It.IsAny<string>()))
                .Returns(string.Empty);

            string actualContents = null;
            this.environmentMock.Setup(x => x.WriteAllText(It.IsAny<string>(), It.IsAny<string>()))
                .Callback<string, string>((x, y) => actualContents = y);

            this.testable.ClassUnderTest.WriteSecret(expectedSecret);

            actualContents.Should().NotBeNullOrEmpty();
            var jsonArray = JArray.Parse(actualContents);
            jsonArray.Should().HaveCount(1);
            var actualSecret = jsonArray[0].ToObject<Secret>();
            AssertEx.PropertyValuesAreEquals(actualSecret, expectedSecret);
        }

        [Fact]
        public void WriteSecret_AppendsSecretToExistingList() {
            var fixture = new Fixture();
            var expectedSecret = fixture.Create<Secret>();

            string actualContents = null;
            this.environmentMock.Setup(x => x.WriteAllText(It.IsAny<string>(), It.IsAny<string>()))
                .Callback<string, string>((x, y) => actualContents = y);

            this.testable.ClassUnderTest.WriteSecret(expectedSecret);
            actualContents.Should().NotBeNullOrEmpty();
            var jsonArray = JArray.Parse(actualContents);
            jsonArray.Should().HaveCount(2);
            var actualSecret = jsonArray[1].ToObject<Secret>();
            AssertEx.PropertyValuesAreEquals(actualSecret, expectedSecret);
        }

        [Fact]
        public void WriteSecret_OverwritesSecretIfMatchingTarget() {
            var fixture = new Fixture();
            var expectedSecret = fixture.Create<Secret>();
            expectedSecret.Identifier = Guid.Empty;

            string actualContents = null;
            this.environmentMock.Setup(x => x.WriteAllText(It.IsAny<string>(), It.IsAny<string>()))
                .Callback<string, string>((x, y) => actualContents = y);

            this.testable.ClassUnderTest.WriteSecret(expectedSecret);

            actualContents.Should().NotBeNullOrEmpty();
            var jsonArray = JArray.Parse(actualContents);
            jsonArray.Should().HaveCount(1);
            var actualSecret = jsonArray[0].ToObject<Secret>();
            AssertEx.PropertyValuesAreEquals(actualSecret, expectedSecret);
        }
    }
}
