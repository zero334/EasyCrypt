package functions;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

public class Zip {

	public static void zip(String[] elementPath, String outputPath) {
		
		int elementCount = elementPath.length - 1;
		
		if(elementCount > 0) {
			
			try {
				FileOutputStream fos = new FileOutputStream("crypted.crpt");
				ZipOutputStream zos = new ZipOutputStream(fos);

				do {
					// Add the element to the archive
					addToZipFile(elementPath[elementCount], zos);
					
					// Delete element which is already in the archive.
					File f = new File(elementPath[elementCount]);
					f.delete();
					
					elementCount--;
				} while (elementCount >= 0);

				zos.close();
				fos.close();

				
			} catch (FileNotFoundException e) {
				e.printStackTrace();
			} catch (IOException e) {
				e.printStackTrace();
			}
		} else {
			System.out.println("Nothing to pack!");
		}
	}
	
	
	public static void unZip(String zipFile, String execPath) {
		 byte[] buffer = new byte[1024];
		 
	     try {
	    	//create output directory is not exists
	    	File folder = new File(execPath);
	    	if(!folder.exists()) {
	    		folder.mkdir();
	    	}
	 
	    	//get the zip file content
	    	ZipInputStream zis = new ZipInputStream(new FileInputStream(zipFile));
	    	//get the zipped file list entry
	    	ZipEntry ze = zis.getNextEntry();
	 
	    	while(ze!=null) {

	    	   String fileName = ze.getName();
	           File newFile = new File(execPath + File.separator + fileName);
	 
	            //create all non exists folders
	            //else you will hit FileNotFoundException for compressed folder
	            new File(newFile.getParent()).mkdirs();
	 
	            FileOutputStream fos = new FileOutputStream(newFile);             

	            int len;
	            while ((len = zis.read(buffer)) > 0) {
	            	fos.write(buffer, 0, len);
	            }

	            fos.close();   
	            ze = zis.getNextEntry();
	    	}

	        zis.closeEntry();
	    	zis.close();

	    } catch(IOException ex) {
	       ex.printStackTrace(); 
	    }
	}




	private static void addToZipFile(String fileName, ZipOutputStream zos) throws FileNotFoundException, IOException {

		File file = new File(fileName);
		FileInputStream fis = new FileInputStream(file);
		ZipEntry zipEntry = new ZipEntry(fileName);
		zos.putNextEntry(zipEntry);

		byte[] bytes = new byte[1024];
		int length;
		while ((length = fis.read(bytes)) >= 0) {
			zos.write(bytes, 0, length);
		}

		zos.closeEntry();
		fis.close();
	}
}