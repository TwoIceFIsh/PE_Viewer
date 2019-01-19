package FileManager;

import java.io.File;
import java.io.IOException;
import java.util.Enumeration;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.oreilly.servlet.MultipartRequest;
import com.oreilly.servlet.multipart.DefaultFileRenamePolicy;
 
@WebServlet("/FileManagerServlet")
public class FileManagerServlet extends HttpServlet {
	private static final long serialVersionUID = 1L;


	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		// TODO Auto-generated method stub

		String uploadPath = request.getRealPath("/uploadFile");
		System.out.println("������ : " + uploadPath + "<br/>");

		int maxSize = 1024 * 1024 * 10; // �ѹ��� �ø� �� �ִ� ���� �뷮 : 10M�� ����

		String name = "";
		String subject = "";

		String fileName1 = ""; // �ߺ�ó���� �̸�
		String originalName1 = ""; // �ߺ� ó���� ���� ���� �̸�
		long fileSize = 0; // ���� ������
		String fileType = ""; // ���� Ÿ��

		MultipartRequest multi = null;

		try{
			// request,����������,�뷮,���ڵ�Ÿ��,�ߺ����ϸ� ���� �⺻ ��å
			multi = new MultipartRequest(request,uploadPath,maxSize,"utf-8",new DefaultFileRenamePolicy());

			// form���� input name="name" �� �༮ value�� ������
			name = multi.getParameter("name");
			// name="subject" �� �༮ value�� ������
			subject = multi.getParameter("subject");

			// ������ ��ü �����̸����� ������
			Enumeration files = multi.getFileNames();

			while(files.hasMoreElements()){
				// form �±׿��� <input type="file" name="���⿡ ������ �̸�" />�� �����´�.
				String file1 = (String)files.nextElement(); // ���� input�� ������ �̸��� ������
				// �׿� �ش��ϴ� ���� ���� �̸��� ������
				originalName1 = multi.getOriginalFileName(file1);
				// ���ϸ��� �ߺ��� ��� �ߺ� ��å�� ���� �ڿ� 1,2,3 ó�� �پ� unique�ϰ� ���ϸ��� �����ϴµ�
				// �̶� ������ �̸��� filesystemName�̶� �Ͽ� �� �̸� ������ �����´�.(�ߺ��� ���� ó��)
				fileName1 = multi.getFilesystemName(file1);
				// ���� Ÿ�� ������ ������
				fileType = multi.getContentType(file1);
				// input file name�� �ش��ϴ� ���� ������ ������
				File file = multi.getFile(file1);
				// �� ���� ��ü�� ũ�⸦ �˾Ƴ�
				fileSize = file.length();
			}
		}catch(Exception e){
			e.printStackTrace();
		}


	}

}
