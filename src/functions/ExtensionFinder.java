package functions;

import java.io.File;
import java.io.FilenameFilter;

public class ExtensionFinder {
 
	public static String findExtention(String path, String extention) {

			File file = new File(path);

			if (file.exists()) {
				File[] files = file.listFiles(new FilenameFilter() {
					@Override
					public boolean accept(File dir, String name) {
						return name.toLowerCase().endsWith(extention);
					}
				});

				for (File alp : files) {
					return alp.getName();
				}
			} else {
				System.out.println(file.getAbsolutePath() + "Foder not exists");
				return "";
			}
			return "";
		}
}