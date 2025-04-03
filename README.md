# Internship

## Q1. Tìm hiểu về cấu trúc của PE file.
1. Ý nghĩa: Định dạng file pe là định dạng của hầu như tất cả các file thực thi trên Windows (exe, dll, com). Với độ phổ biến của hệ điều hành Windows đến hơn 80% các loại mã độc trên thế giới được thực thi trên cấu trúc này.
2. Yêu cầu: Viết một chương trình bằng c\c++ đọc và in ra tất cả các trường trong pe header của bất kỳ file thực thi nào trên Windows 7/8/10.
3. Keyword: Pe header.

## Q2. Tạo ra một Trojan
1. Ý nghĩa: Sau khi đã hiểu được cấu trúc của PE file, ta sẽ tìm hiểu về phương thức lây nhiễm lâu đời nhất của malware là pe injection. Đây là phương thức để tạo ra một trojan.
2. Yêu cầu: Viết một công cụ bằng c\c++ chèn một đoạn code có chức năng popup một messagebox với nội dung "you are infected" vào một file pe bất kỳ. File pe sau khi bị inject, lúc chạy nó sẽ hiển thị messagebox rồi sau đó hoạt động bình thường.
3. Keyword: Pe injection, Address of entry point, section header, shellcode.

## Q3. Viết một đoạn mã Position-independent code
1. Ý nghĩa: Malware được tạo ra nhằm mục đích hoạt động trên nhiều hệ thống khác nhau. Vậy nên mã độc khi chạy phải hoạt động mà không phụ thuộc vào bất kỳ file nào hay tiến trình nào.
2. Yêu cầu: Viết một đoạn shellcode bằng masm. Shellcode có chức năng chèn chính bản thân nó vào tất cả các file pe khác trong cùng thư mục hiện hành. Shellcode sẽ phải tự load các hàm winapi cho chính bản thân nó.
3. Ví dụ: dùng công cụ của bài 2 chèn PIC shellcode vào một file pe bất kỳ => Khi chạy file pe nó sẽ lây nhiễm tất cả file trong cùng thư mục với nó => đem file bất kỳ bị lây nhiễm trong thư mục đó sang máy khác và chạy nó sẽ tiếp tục lây nhiễm.
4. Keyword: Position-independent code, kỹ thuật delta, Dynamically Retrieving WinAPI Functions
