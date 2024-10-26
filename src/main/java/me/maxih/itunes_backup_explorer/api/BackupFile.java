package me.maxih.itunes_backup_explorer.api;

import com.dd.plist.*;
import me.maxih.itunes_backup_explorer.util.BackupPathUtils;
import me.maxih.itunes_backup_explorer.util.UtilDict;
import org.bouncycastle.util.Arrays;
import org.xml.sax.SAXException;

import javax.xml.parsers.ParserConfigurationException;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.SQLException;
import java.text.ParseException;
import java.util.HexFormat;
import java.util.NoSuchElementException;
import java.util.Optional;

public class BackupFile {
    public final ITunesBackup backup;
    public final UtilDict data;
    public final String fileID;
    public final String domain;
    public final String relativePath;
    public final int flags;

    private final FileType fileType;

    private final UtilDict properties;
    private final NSObject[] objects;

    private File contentFile = null;
    private String symlinkTarget = null;

    private long size;
    private int protectionClass;
    private byte[] encryptionKey = null;
    private byte[] digest = null;

    private static String computeRelativePathForClone(BackupFile cloneFrom, String newFileName) {
        return BackupPathUtils.getParentPath(cloneFrom.relativePath) + BackupPathUtils.SEPARATOR + newFileName;
    }

    private static String computeFileId(String domain, String relativePath) throws NoSuchAlgorithmException {
        final MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] digest = md.digest((domain + "-" + relativePath).getBytes(StandardCharsets.UTF_8));
        return HexFormat.of().withLowerCase().formatHex(digest);
    }

    // in support of cloneToNewFile
    private BackupFile(BackupFile cloneFrom, String newFileName)
            throws IOException, PropertyListFormatException, ParseException, ParserConfigurationException, SAXException, BackupReadException, NoSuchAlgorithmException {
        this(cloneFrom, newFileName, computeRelativePathForClone(cloneFrom, newFileName));
    }

    // internal - invoked by above constructor
    private BackupFile(BackupFile cloneFrom, String newFileName, String computedRelativePath)
            throws IOException, PropertyListFormatException, ParseException, ParserConfigurationException, SAXException, BackupReadException, NoSuchAlgorithmException {
        this(cloneFrom.backup,
                computeFileId(cloneFrom.domain, computedRelativePath),
                cloneFrom.domain,
                computedRelativePath,
                cloneFrom.flags,
                (NSDictionary) PropertyListParser.parse(BinaryPropertyListWriter.writeToArray(cloneFrom.data.dict)),
                false);
    }

    public BackupFile(ITunesBackup backup, String fileID, String domain, String relativePath, int flags, NSDictionary data) throws BackupReadException {
        this(backup, fileID, domain, relativePath, flags, data, true);
    }

    private BackupFile(ITunesBackup backup, String fileID, String domain, String relativePath, int flags, NSDictionary data, boolean verifyExistsOnDisk) throws BackupReadException {
        this.backup = backup;
        this.fileID = fileID;
        this.domain = domain;
        this.relativePath = relativePath;
        this.flags = flags;
        this.data = new UtilDict(data);

        this.fileType = FileType.fromFlags(flags);

        try {
            this.objects = this.data.getArray("$objects").orElseThrow();
            this.properties = new UtilDict(this.getObject(NSDictionary.class, this.data.get(UID.class, "$top", "root").orElseThrow()));

            if (this.fileType == FileType.FILE) {
                this.contentFile = Paths.get(backup.directory.getAbsolutePath(), fileID.substring(0, 2), fileID).toFile();
                if (verifyExistsOnDisk && !this.contentFile.exists())
                    throw new BackupReadException("Missing file: " + this.fileID + " in " + domain + " (" + relativePath + ")");

                this.size = this.properties.get(NSNumber.class, "Size").orElseThrow().longValue();
                this.protectionClass = this.properties.get(NSNumber.class, "ProtectionClass").orElseThrow().intValue();

                Optional<UID> encryptionKeyUID = this.properties.get(UID.class, "EncryptionKey");
                if (encryptionKeyUID.isPresent()) {
                    this.encryptionKey = new byte[40];
                    ByteBuffer encryptionKeyBuffer = ByteBuffer.wrap(this.encryptionKey);
                    new UtilDict(this.getObject(NSDictionary.class, encryptionKeyUID.get()))
                            .getData("NS.data")
                            .orElseThrow()
                            .getBytes(encryptionKeyBuffer, 4, 40);
                } else {
                    this.encryptionKey = null;
                }

                Optional<UID> digestUID = this.properties.get(UID.class, "Digest");
                digestUID.ifPresent(uid -> this.digest = this.getObject(NSData.class, uid).bytes());
            } else if (this.fileType == FileType.SYMBOLIC_LINK) {
                Optional<UID> targetUID = this.properties.get(UID.class, "Target");
                if (targetUID.isPresent()) {
                    this.symlinkTarget = this.getObject(NSString.class, targetUID.get()).getContent();
                } else {
                    throw new BackupReadException("Missing target of symbolic link '" + domain + ":" + relativePath + "'");
                }
            }
        } catch (NoSuchElementException e) {
            throw new BackupReadException(e);
        }
    }

    private <T extends NSObject> T getObject(Class<T> type, UID uid) throws NoSuchElementException {
        byte index = uid.getBytes()[0];
        Object obj = this.objects[index];
        if (type.isInstance(obj)) return type.cast(obj);
        throw new NoSuchElementException();
    }

    private void setObject(UID uid, NSObject object) {
        byte index = uid.getBytes()[0];
        this.objects[index] = object;
        // theoretically not necessary, but don't rely on the array never being cloned
        this.data.put("$objects", new NSArray(this.objects));
    }

    public FileType getFileType() {
        return fileType;
    }

    public File getContentFile() {
        return contentFile;
    }

    public long getSize() {
        return size;
    }

    public boolean isEncrypted() {
        return this.encryptionKey != null;
    }

    public String getFileName() {
        return BackupPathUtils.getFileName(this.relativePath);
    }

    public String getFileExtension() {
        return BackupPathUtils.getFileExtension(this.relativePath);
    }

    public String getParentPath() {
        return BackupPathUtils.getParentPath(this.relativePath);
    }

    public String getSymlinkTarget() {
        return this.symlinkTarget;
    }

    public BackupFile cloneToNewFile(String newFileName, File newFileContent)
            throws BackupReadException, PropertyListFormatException, IOException, ParseException,
            ParserConfigurationException, SAXException, DatabaseConnectionException, UnsupportedCryptoException,
            NotUnlockedException, InvalidKeyException, NoSuchAlgorithmException, SQLException {
        BackupFile newBackupFile = new BackupFile(this, newFileName);

        if (newBackupFile.backup.manifest.getKeyBag().isPresent()) {
            newBackupFile.encryptionKey = newBackupFile.backup.manifest.getKeyBag().get()
                    .generateAndWrapKeyForClass(newBackupFile.protectionClass);
            UID encryptionKeyUid = newBackupFile.properties.get(UID.class, "EncryptionKey").orElseThrow();
            UtilDict utilDict = new UtilDict(newBackupFile.getObject(NSDictionary.class, encryptionKeyUid));
            NSData originalNsData = utilDict.getData("NS.data")
                    .orElseThrow();
            byte[] originalKeyPrefix = new byte[4];
            originalNsData.getBytes(ByteBuffer.wrap(originalKeyPrefix), 0, 4);
            NSData newNsData = new NSData(Arrays.concatenate(originalKeyPrefix, newBackupFile.encryptionKey));
            utilDict.put("NS.data", newNsData);
            newBackupFile.setObject(encryptionKeyUid, utilDict.dict);
        }

        newBackupFile.properties.put(
                "InodeNumber",
                new NSNumber(newBackupFile.backup.computeNextAvailableInodeNumber()));
        UID propertiesUid = newBackupFile.data.get(UID.class, "$top", "root").orElseThrow();
        newBackupFile.setObject(propertiesUid, newBackupFile.properties.dict);

        UID relativePathUid = newBackupFile.properties.get(UID.class, "RelativePath").orElseThrow();
        newBackupFile.setObject(relativePathUid, new NSString(newBackupFile.relativePath));

        newBackupFile.replaceWith(newFileContent, true);
        newBackupFile.backup.insertNewFile(
                newBackupFile.fileID,
                newBackupFile.domain,
                newBackupFile.relativePath,
                newBackupFile.flags,
                newBackupFile.data.dict);
        return newBackupFile;
    }

    /**
     * Files in system domains (excluding camera roll, media and tones)
     * have SHA-1 hashes of the (encrypted) content files in the database.
     * iTunes checks them while recovering backups.
     *
     * @return The digest bytes or null if the file does not have one
     */
    public byte[] getDigest() {
        return this.digest;
    }

    byte[] calcFileDigest() throws IOException, UnsupportedCryptoException {
        try {
            MessageDigest sha1Digest = MessageDigest.getInstance("SHA-1");
            try (
                    BufferedInputStream contentInputStream = new BufferedInputStream(new FileInputStream(this.contentFile))
            ) {
                byte[] buffer = new byte[8192];
                int len = contentInputStream.read(buffer);
                while (len > 0) {
                    sha1Digest.update(buffer, 0, len);
                    len = contentInputStream.read(buffer);
                }
                return sha1Digest.digest();
            }
        } catch (NoSuchAlgorithmException e) {
            throw new UnsupportedCryptoException(e);
        }
    }

    public void extract(File destination)
            throws IOException, BackupReadException, NotUnlockedException, UnsupportedCryptoException, UnsupportedOperationException {

        switch (this.fileType) {
            case DIRECTORY:
                if (!destination.exists()) Files.createDirectory(destination.toPath());
                break;
            case FILE:
                if (this.isEncrypted()) {
                    if (this.backup.manifest.getKeyBag().isEmpty())
                        throw new BackupReadException("Encrypted file in non-encrypted backup");

                    try {
                        this.backup.manifest.getKeyBag().get().decryptFile(this.protectionClass, this.encryptionKey, this.contentFile, destination);
                    } catch (InvalidKeyException e) {
                        throw new BackupReadException(e);
                    }

                    //noinspection ResultOfMethodCallIgnored
                    this.properties.get(NSNumber.class, "LastModified")
                            .map(NSNumber::longValue)
                            .map(seconds -> seconds * 1000)
                            .ifPresent(destination::setLastModified);
                } else {
                    Files.copy(this.contentFile.toPath(), destination.toPath(),
                            StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.COPY_ATTRIBUTES);
                }
                break;
            case SYMBOLIC_LINK:
                throw new UnsupportedOperationException("Not implemented yet");
        }

    }

    public void extractToFolder(File destinationFolder, boolean withRelativePath)
            throws IOException, BackupReadException, NotUnlockedException, UnsupportedCryptoException, UnsupportedOperationException {

        String relative;

        try {
            relative = withRelativePath ? Paths.get(this.domain, this.relativePath).toString() : this.getFileName();
        } catch (InvalidPathException e) {
            try {
                relative = withRelativePath
                        ? Paths.get(this.domain, BackupPathUtils.cleanPath(this.relativePath)).toString()
                        : BackupPathUtils.cleanPath(this.getFileName());
                System.out.println("Continuing with invalid characters replaced: " + this.getFileName() + " -> " + relative);
            } catch (InvalidPathException e1) {
                throw new IOException("Invalid character in filename, failed to replace", e1);
            }
        }
        File destination = new File(destinationFolder.getAbsolutePath(), relative);
        if (destination.exists() && this.fileType != FileType.DIRECTORY)
            throw new FileAlreadyExistsException(destination.getAbsolutePath());

        Files.createDirectories(destination.getParentFile().toPath());
        this.extract(destination);
    }

    public void replaceWith(File newFile) throws IOException, BackupReadException, UnsupportedCryptoException, NotUnlockedException, DatabaseConnectionException {
        replaceWith(newFile, false);
    }

    public void replaceWith(File newFile, boolean skipBackup) throws IOException, BackupReadException, UnsupportedCryptoException, NotUnlockedException, DatabaseConnectionException {
        BasicFileAttributes newFileAttributes = Files.readAttributes(newFile.toPath(), BasicFileAttributes.class);
        if (!newFileAttributes.isRegularFile()) throw new IOException("Not a file");
        if (this.fileType != FileType.FILE) throw new UnsupportedOperationException("Not implemented yet");
        if (!skipBackup) {
            this.backupOriginal();
        }
        this.size = newFileAttributes.size();
        this.properties.put("Size", this.size);
        if (this.isEncrypted()) {
            if (this.backup.manifest.getKeyBag().isEmpty())
                throw new BackupReadException("Encrypted file in non-encrypted backup");

            try {
                this.backup.manifest.getKeyBag().get().encryptFile(this.protectionClass, this.encryptionKey, newFile, this.contentFile);
            } catch (InvalidKeyException e) {
                throw new BackupReadException(e);
            }
        } else {
            Files.copy(newFile.toPath(), this.contentFile.toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.COPY_ATTRIBUTES);
        }

        Optional<UID> digestUID = this.properties.get(UID.class, "Digest");
        if (digestUID.isPresent()) {
            byte[] newDigest = this.calcFileDigest();
            this.setObject(digestUID.get(), new NSData(newDigest));
        }

        this.backup.updateFileInfo(this.fileID, this.data.dict);
    }

    /**
     * Removes this backup file from the database and
     * deletes the content file if there is one.<br>
     * Important: This does not remove directories recursively,
     * so child nodes could be left without a parent.
     *
     * @throws IOException                 if the content file could not be deleted
     * @throws DatabaseConnectionException if the database connection failed
     */
    public void delete() throws IOException, DatabaseConnectionException {
        try {
            this.backupOriginal(true);
        } catch (FileNotFoundException e) {
            System.out.printf("Warning: Deleted backup file '%s' did not have a content file%n", this.relativePath);
        }
        this.backup.removeFileFromDatabase(this.fileID);
    }

    /**
     * Backs up the current state of the file in a separate directory.
     *
     * @param move If true, move the content file instead of copying it
     * @throws FileNotFoundException if the content file is missing (and the file is not a symlink/directory)
     * @throws IOException           if the file could not be copied/moved to the backup explorer subdirectory.
     */
    private void backupOriginal(boolean move) throws IOException {
        File dir = new File(this.backup.directory, "_BackupExplorer");
        if (!dir.isDirectory() && !dir.mkdir())
            throw new IOException("Backup directory '" + dir.getAbsolutePath() + "' could not be created");

        // Incremental suffix
        String backupName = this.fileID;
        int i = 0;
        while (new File(dir, backupName + ".plist").exists() || new File(dir, backupName + ".bak").exists()) {
            backupName = this.fileID + "." + (++i);
        }

        BinaryPropertyListWriter.write(this.data.dict, new File(dir, backupName + ".plist"));

        if (this.contentFile != null && this.contentFile.exists()) {
            if (move)
                Files.move(this.contentFile.toPath(), new File(dir, backupName + ".bak").toPath());
            else
                Files.copy(this.contentFile.toPath(), new File(dir, backupName + ".bak").toPath());
        } else if (this.fileType == FileType.FILE) {
            throw new FileNotFoundException("Missing content file '" + this.fileID + "' of '" + domain + ":" + relativePath + "'");
        }
    }

    private void backupOriginal() throws IOException {
        backupOriginal(false);
    }

    public enum FileType {
        FILE(1),
        DIRECTORY(2),
        SYMBOLIC_LINK(4);

        public final int flag;

        FileType(int flag) {
            this.flag = flag;
        }

        public static FileType fromFlags(int flags) throws BackupReadException {
            for (FileType type : values()) {
                if (type.flag == flags) return type;
            }

            throw new BackupReadException("Unknown file type " + flags);
        }
    }
}
