namespace SafeNet.Acl.Test {
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Security;
    using System.Security.AccessControl;
    using System.Security.Principal;

    using FluentAssertions;

    using Moq;

    using Ploeh.AutoFixture;
    using Ploeh.AutoFixture.Xunit;

    using SafeNet.Acl.Storage;
    using SafeNet.Core;
    using SafeNet.Test.Common;

    using Xunit;
    using Xunit.Extensions;

    public class FileAclSafeTests : IDisposable {
        #region Constants

        private const string ExpectedTarget = "Hello World";

        #endregion

        #region Fields

        private readonly Mock<EnvironmentWrapper> environmentMock;

        private readonly string expectedFileName;

        private readonly Testable<FileAclSafe> testable;

        #endregion

        #region Constructors and Destructors

        public FileAclSafeTests() {
            this.testable = new Testable<FileAclSafe>();
            this.environmentMock = this.testable.InjectMock<EnvironmentWrapper>();
            this.expectedFileName = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
            this.testable.Fixture.Register(() => new SecureString());
        }

        #endregion

        #region Public Methods and Operators

        public void Dispose() {
            if (File.Exists(this.expectedFileName)) {
                File.Delete(this.expectedFileName);
            }
        }

        [Theory]
        [Integration]
        [AutoData]
        public void GivenSafeStringPathCanStoreSecret(Secret expectedSecret) {
            var safe = new FileAclSafe(this.expectedFileName);
            safe.StoreSecret(expectedSecret);

            ISecret actualSecret = safe.RetrieveSecret(expectedSecret.Target);

            AssertEx.CompareSecrets(actualSecret, expectedSecret);
        }

        [Fact]
        public void Protect_AssignsFileSystemAccessRulesToSafe() {
            this.RegisterCurrentUserInFixture();
            FileInfo realFile = this.RegisterRandomFileAsSafe(true);
            FileSecurity security = realFile.GetAccessControl();

            this.environmentMock.Setup(x => x.SetAccessControl(It.IsAny<FileInfo>(), It.IsAny<FileSystemSecurity>()))
                .Verifiable();

            this.testable.ClassUnderTest.Protect(security);
            this.environmentMock.Verify(
                x => x.SetAccessControl(this.testable.ClassUnderTest.SafeObject, security), 
                Times.Once());
        }

        [Fact]
        public void Protect_WithRulesAssignsRulesToSafe() {
            this.RegisterCurrentUserInFixture();
            this.RegisterRandomFileAsSafe(this.expectedFileName, true);
            this.testable.Fixture.Register(() => InheritanceFlags.None);
            this.testable.Fixture.Register(() => PropagationFlags.None);
            List<FileSystemAccessRule> expectedRules = this.testable.Fixture.CreateMany<FileSystemAccessRule>().ToList();

            FileSystemSecurity actualSecurity = null;
            this.environmentMock.Setup(x => x.SetAccessControl(It.IsAny<FileInfo>(), It.IsAny<FileSystemSecurity>()))
                .Callback<FileSystemInfo, FileSystemSecurity>((x, y) => actualSecurity = y);

            this.testable.ClassUnderTest.Protect(expectedRules);

            AuthorizationRuleCollection actualRules = actualSecurity.GetAccessRules(
                true, 
                true, 
                typeof(SecurityIdentifier));

            actualRules.ShouldBeEquivalentTo(expectedRules);
        }

        [Theory, AutoData]
        public void SearchSecrets_WithNoneSearchMethod(IList<ISecret> expectedSecrets) {
            var storageMock = this.testable.InjectMock<IStorageSchema>();
            storageMock.Setup(x => x.GetSecrets()).Returns(expectedSecrets);
            var expectedTarget = expectedSecrets[0].Target;

            var actualSecrets = this.testable.ClassUnderTest.SearchSecrets(expectedTarget, SafeSearchMethod.None);

            actualSecrets.Should().NotBeNull();
            actualSecrets.Should().HaveCount(1);
            actualSecrets[0].Target.Should().Be(expectedTarget);
        }

        [Theory, AutoData]
        public void SearchSecrets_WithNoneSearchMethod_WhenNoMatch_ExpectEmptyList(IList<ISecret> expectedSecrets) {
            var storageMock = this.testable.InjectMock<IStorageSchema>();
            storageMock.Setup(x => x.GetSecrets()).Returns(expectedSecrets);

            var actualSecrets = this.testable.ClassUnderTest.SearchSecrets(
                Guid.NewGuid().ToString(),
                SafeSearchMethod.None);

            actualSecrets.Should().BeEmpty();
        }

        [Theory, AutoData]
        public void SearchSecrets_WithRegexCardSearch(IList<ISecret> expectedSecrets) {
            var storageMock = this.testable.InjectMock<IStorageSchema>();
            storageMock.Setup(x => x.GetSecrets()).Returns(expectedSecrets);
            const string SearchPattern = @"^.*$";

            var actualSecrets = this.testable.ClassUnderTest.SearchSecrets(SearchPattern, SafeSearchMethod.Regex);

            actualSecrets.Should().NotBeNull();
            actualSecrets.Should().HaveCount(expectedSecrets.Count);
        }

        [Theory, AutoData]
        public void Searchsecrets_WithRegexSearch_WhenNoMatch_ExpectNull(IList<ISecret> expectedSecrets) {
            var storageMock = this.testable.InjectMock<IStorageSchema>();
            storageMock.Setup(x => x.GetSecrets()).Returns(expectedSecrets);
            const string BadPattern = "Foo.*";

            var actualSecret = this.testable.ClassUnderTest.SearchSecrets(BadPattern, SafeSearchMethod.Regex);

            actualSecret.Should().BeEmpty();
        }

        [Theory, AutoData]
        public void SearchSecrets_WithWildCardSearch(IList<ISecret> expectedSecrets) {
            var storageMock = this.testable.InjectMock<IStorageSchema>();
            storageMock.Setup(x => x.GetSecrets()).Returns(expectedSecrets);
            const string SearchPattern = "*";

            var actualSecrets = this.testable.ClassUnderTest.SearchSecrets(
                SearchPattern, 
                SafeSearchMethod.Wildcard);

            actualSecrets.Should().NotBeNull();
            actualSecrets.Should().HaveCount(expectedSecrets.Count);
        }

        [Theory, AutoData]
        public void SearchSecrets_WithWildCardSearch_WhenNoMatch_ExpectNull(IList<ISecret> expectedSecrets) {
            var storageMock = this.testable.InjectMock<IStorageSchema>();
            storageMock.Setup(x => x.GetSecrets()).Returns(expectedSecrets);
            const string BadPattern = "Foo*";

            var actualSecrets = this.testable.ClassUnderTest.SearchSecrets(BadPattern, SafeSearchMethod.Wildcard);

            actualSecrets.Should().BeEmpty();
        }

        [Theory, AutoData]
        public void RetrieveSecret_OnlyTarget_ExpectMatch(IList<Secret> expectedSecrets) {
            var storageMock = this.testable.InjectMock<IStorageSchema>();
            storageMock.Setup(x => x.GetSecrets()).Returns<IList<ISecret>>(list => expectedSecrets);

            var actualSecret = this.testable.ClassUnderTest.RetrieveSecret(expectedSecrets[0].Target);

            actualSecret.Should().Be(expectedSecrets[0]);
        }

        [Theory, AutoData]
        public void Upsert_IfCredentialDoesNotExist_ExpectInserted(Secret expectedSecret) {
            this.RegisterRandomFileAsSafe();
            this.environmentMock.Setup(x => x.FileExists(It.IsAny<string>())).Returns(true);

            Mock<IStorageSchema> mockStorage = this.testable.InjectMock<IStorageSchema>();
            mockStorage.Setup(x => x.GetSecrets()).Returns<IList<ISecret>>(list => new ISecret[0]);

            mockStorage.Setup(x => x.WriteSecret(It.IsAny<ISecret>())).Verifiable();

            this.testable.ClassUnderTest.UpsertSecret(expectedSecret);

            mockStorage.Verify(x => x.WriteSecret(expectedSecret), Times.Once());
        }

        [Theory]
        [AutoData]
        public void Upsert_IfCredentialExists_ExpectWriteWith(Secret expectedSecret, Secret actualSecret) {
            this.RegisterRandomFileAsSafe();
            this.environmentMock.Setup(x => x.FileExists(It.IsAny<string>())).Returns(true);

            Mock<IStorageSchema> mockStorage = this.testable.InjectMock<IStorageSchema>();
            mockStorage.Setup(x => x.GetSecrets()).Returns<IList<ISecret>>(list => new ISecret[] { actualSecret });

            ISecret writtenSecret = null;
            mockStorage.Setup(x => x.WriteSecret(It.IsAny<ISecret>())).Callback<ISecret>(x => writtenSecret = x);

            this.testable.ClassUnderTest.UpsertSecret(expectedSecret);

            AssertEx.CompareSecrets(writtenSecret, expectedSecret, false);
            writtenSecret.Identifier.Should().Be(actualSecret.Identifier);
        }

        [Fact]
        public void WhenConstructedAndFileExistsNoChange() {
            this.RegisterRandomFileAsSafe();
            this.environmentMock.Setup(x => x.FileExists(this.expectedFileName)).Returns(true).Verifiable();

            FileAclSafe actual = this.testable.ClassUnderTest;

            this.environmentMock.Verify(x => x.WriteAllText(It.IsAny<string>(), It.IsAny<string>()), Times.Never());
        }

        [Fact]
        public void WhenConstructedGivenNonExistantSafeFileCreatesFileAndDirectoryStructure() {
            FileInfo safe = this.RegisterRandomFileAsSafe();
            this.environmentMock.Setup(x => x.FileExists(this.expectedFileName)).Returns(false).Verifiable();

            FileAclSafe actual = this.testable.ClassUnderTest;

            this.environmentMock.Verify(x => x.CreateDirectory(safe.DirectoryName), Times.Once());
            this.environmentMock.Verify(x => x.WriteAllText(this.expectedFileName, It.IsAny<string>()), Times.Once());
        }

        #endregion

        #region Methods

        private void RegisterCurrentUserInFixture() {
            this.testable.Fixture.Register<IdentityReference>(() => new NTAccount(WindowsIdentity.GetCurrent().Name));
        }

        private FileInfo RegisterRandomFileAsSafe(bool writeText = false) {
            return this.RegisterRandomFileAsSafe(this.expectedFileName, writeText);
        }

        private FileInfo RegisterRandomFileAsSafe(string path, bool writeText = false) {
            if (writeText) {
                File.WriteAllText(path, string.Empty);
            }
            var safe = new FileInfo(path);
            this.testable.Fixture.Register(() => safe);

            return safe;
        }

        #endregion
    }
}