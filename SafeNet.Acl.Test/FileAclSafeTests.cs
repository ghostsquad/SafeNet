namespace SafeNet.Acl.Test {
    using System;
    using System.IO;
    using System.Linq;
    using System.Security;
    using System.Security.AccessControl;
    using System.Security.Principal;

    using FluentAssertions;

    using Moq;

    using Ploeh.AutoFixture;
    using Ploeh.AutoFixture.Kernel;

    using SafeNet.Acl.Storage;
    using SafeNet.Core;
    using SafeNet.Test.Common;

    using Xunit;

    public class FileAclSafeTests : IDisposable {
        private readonly Mock<EnvironmentWrapper> environmentMock;

        private readonly string expectedFileName;

        private readonly Testable<FileAclSafe> testable;

        public FileAclSafeTests() {
            this.testable = new Testable<FileAclSafe>();
            this.testable.Fixture.Customize<FileAclSafe>(c => c.FromFactory(
                new MethodInvoker(
                    new GreedyConstructorQuery())));
            this.environmentMock = this.testable.InjectMock<EnvironmentWrapper>();
            this.expectedFileName = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
            this.testable.Fixture.Register(() => new SecureString());
        }

        public void Dispose() {
            if (File.Exists(this.expectedFileName)) {
                File.Delete(this.expectedFileName);
            }
        }

        [Fact]
        public void Protect_AssignsFileSystemAccessRulesToSafe() {
            var realFile = this.GetRealRandomFile();
            var security = realFile.GetAccessControl();

            this.RegisterCurrentUserInFixture();
            this.testable.Fixture.Register(() => realFile);
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
            this.testable.Fixture.Register(this.GetRealRandomFile);
            this.testable.Fixture.Register(() => InheritanceFlags.None);
            this.testable.Fixture.Register(() => PropagationFlags.None);
            var expectedRules = this.testable.Fixture.CreateMany<FileSystemAccessRule>().ToList();

            FileSystemSecurity actualSecurity = null;
            this.environmentMock.Setup(x => x.SetAccessControl(It.IsAny<FileInfo>(), It.IsAny<FileSystemSecurity>()))
                .Callback<FileSystemInfo, FileSystemSecurity>((x, y) => actualSecurity = y);

            this.testable.ClassUnderTest.Protect(expectedRules);

            var actualRules = actualSecurity.GetAccessRules(true, true, typeof(SecurityIdentifier));

            actualRules.ShouldBeEquivalentTo(expectedRules);
        }

        [Fact]
        public void RetrieveSecret_OnlyTarget_ExpectSafeSearchNone() {
            this.RegisterCurrentUserInFixture();
            var realFile = this.GetRealRandomFile();
            this.testable.Fixture.Register(() => realFile);
            this.testable.Fixture.Register(realFile.GetAccessControl);
            var storage = this.testable.InjectMock<IStorageSchema>();
            storage.Setup(x => x.ReadSecret(It.IsAny<string>(), SafeSearchMethod.None)).Verifiable();

            this.testable.ClassUnderTest.RetrieveSecret(this.testable.Fixture.Create<string>());

            storage.Verify(x => x.ReadSecret(It.IsAny<string>(), SafeSearchMethod.None));
        }

        [Fact]
        public void WhenConstructedAndFileExistsNoChange() {
            this.testable.Fixture.Register(() => new FileInfo(this.expectedFileName));
            this.environmentMock.Setup(x => x.FileExists(this.expectedFileName)).Returns(true).Verifiable();

            var actual = this.testable.ClassUnderTest;

            this.environmentMock.Verify(x => x.WriteAllText(It.IsAny<string>(), It.IsAny<string>()), Times.Never());
        }

        [Fact]
        public void WhenConstructedGivenNonExistantSafeFileCreatesFileAndDirectoryStructure() {
            var safeObject = new FileInfo(this.expectedFileName);
            this.testable.Fixture.Register(() => safeObject);
            this.testable.Fixture.Register(() => new FileInfo(this.expectedFileName));
            this.environmentMock.Setup(x => x.FileExists(this.expectedFileName)).Returns(false).Verifiable();

            var actual = this.testable.ClassUnderTest;

            this.environmentMock.Verify(x => x.CreateDirectory(safeObject.DirectoryName), Times.Once());
            this.environmentMock.Verify(x => x.WriteAllText(this.expectedFileName, It.IsAny<string>()), Times.Once());
        }


        private FileInfo GetRealRandomFile() {
            File.WriteAllText(this.expectedFileName, string.Empty);
            return new FileInfo(this.expectedFileName);
        }

        private void RegisterCurrentUserInFixture() {
            this.testable.Fixture.Register<IdentityReference>(() => new NTAccount(WindowsIdentity.GetCurrent().Name));
        }
    }
}