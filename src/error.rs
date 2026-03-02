#[derive(Debug)]
pub enum Error {
    FailedToReadLine,
    FailedToFlush,
    FailedToOpenFile,
    FailedToCreateFile,
    FailedToGetFileMetadata,
    FailedToReadFile,
    FailedToWriteToFile,
    FailedToSeekInFile,

    InvalidServerUrl,
    FailedToGenerateSecureRandomBytes,
    Argon2IdHashingError,
    InvalidStateFile,

    InvalidXChaCha20PaddingLength,
    InvalidXChaCha20KeyLength,
    InvalidXChaCha20NonceLength,
    XChaCha20EncryptionFailed,
    XChaCha20DecryptionFailed,
    XChaCha20MalformedPadding,

    StateFileTooLargeToReadIntoMemory,

    FailedToConvertBytesToUtf8,
    FailedToDecodeBase64,
    FailedToSplitLineOnce,

    StateFileCorrupted


}
