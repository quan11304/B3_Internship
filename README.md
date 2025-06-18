# Internship

## Exercises
1. Tìm hiểu về cấu trúc của PE file.
- **Ý nghĩa**: Định dạng file pe là định dạng của hầu như tất cả các file thực thi trên Windows (exe, dll, com). Với độ phổ biến của hệ điều hành Windows đến hơn 80% các loại mã độc trên thế giới được thực thi trên cấu trúc này.
- **Yêu cầu**: Viết một chương trình bằng c\c++ đọc và in ra tất cả các trường trong pe header của bất kỳ file thực thi nào trên Windows 7/8/10.
- **Keyword**: Pe header.

2. Tạo ra một Trojan
- **Ý nghĩa**: Sau khi đã hiểu được cấu trúc của PE file, ta sẽ tìm hiểu về phương thức lây nhiễm lâu đời nhất của malware là pe injection. Đây là phương thức để tạo ra một trojan.
- **Yêu cầu**: Viết một công cụ bằng c\c++ chèn một đoạn code có chức năng popup một messagebox với nội dung "you are infected" vào một file pe bất kỳ. File pe sau khi bị inject, lúc chạy nó sẽ hiển thị messagebox rồi sau đó hoạt động bình thường.
- **Keyword**: Pe injection, Address of entry point, section header, shellcode.

3. Viết một đoạn mã Position-independent code
- **Ý nghĩa**: Malware được tạo ra nhằm mục đích hoạt động trên nhiều hệ thống khác nhau. Vậy nên mã độc khi chạy phải hoạt động mà không phụ thuộc vào bất kỳ file nào hay tiến trình nào.
- **Yêu cầu**: Viết một đoạn shellcode bằng masm. Shellcode có chức năng chèn chính bản thân nó vào tất cả các file pe khác trong cùng thư mục hiện hành. Shellcode sẽ phải tự load các hàm winapi cho chính bản thân nó.
- **Ví dụ**: dùng công cụ của bài 2 chèn PIC shellcode vào một file pe bất kỳ => Khi chạy file pe nó sẽ lây nhiễm tất cả file trong cùng thư mục với nó => đem file bất kỳ bị lây nhiễm trong thư mục đó sang máy khác và chạy nó sẽ tiếp tục lây nhiễm.
- **Keyword**: Position-independent code, kỹ thuật delta, Dynamically Retrieving WinAPI Functions

## Progress
1. _Done_
2. _Done_ (basically)
- Add 64-bit code
- Add a mechanism in case section header does not have space to inject: Move first section to last
3. **In Progress**
- Edit code indentation
- Remove filePath data region
- Edit new AddressOfEntryPoint
- Edit in old_entry for each individual executable
- Reorder all stack variables
- Revalidate run-time operators that should've been compile time operators (Use registers in daccess macro, with a default register parameter)
- Check for errors (file opening, file reading, file pointer set, etc.)
- Loop to scan all files in a folder (FindNextFile at the end of loop)
- Scan for an already in-place injection (will be part of an extra task)
