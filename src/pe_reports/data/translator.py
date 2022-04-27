"""Translate dataframe text to english."""

# Standard Python Libraries
import time

# Third-Party Libraries
from googletrans import Translator


# string = "此项工作由美国土安全部（@{{EMAIL}}@sixgill-end-highlight@ 网络安全和基础设施安全局 CISA 总体领导，国土安全部指挥中心连接了数百名网络安全专家，包括来自美国网络司令部、国务院、国家安全局、联邦调查局，脸谱、推特之类的公司，以及州、县和私营部门网络监控团队的代表。具体执行方面，位于华盛顿特区的国土安全部高科技国家行动中心将密切监控潜在问题；位于弗吉尼亚州的第二个国土安全部指挥中心将专门监视与网络相关的问题，包括外国干涉；网络司令部则将在华盛顿特区第三个指挥中心监控相关事件。"
# translator = Translator()
# translation = translator.translate(string, dest='en').text
# print(translation)
def translate(df, column_list=[]):
    """Translate a given dataframe."""
    print("Beginning to translate.")
    translator = Translator()
    df_en = df.copy()
    if not column_list:
        column_list = df.columns.values.tolist()
    translations = {}
    for column in column_list:
        # unique elements of the column
        unique_elements = df_en[column].unique()
        element_count = 1
        for element in unique_elements:
            print(f"Element #{element_count}/{len(unique_elements)}")
            element_count += 1
            if element:
                count = 1
                while True:
                    try:
                        if count == 6:
                            print("Not trying anymore sorry")
                            break
                        element = str(element)
                        stripped = str(element).strip()
                        max_val = 1000
                        if len(stripped) > max_val:
                            chunks = [
                                stripped[i : i + max_val]
                                for i in range(0, len(stripped), max_val)
                            ]
                            combined_element = ""
                            for chunk in chunks:
                                if chunk:
                                    print(chunk)
                                    combined_element = (
                                        combined_element
                                        + translator.translate(chunk, dest="en").text
                                    )
                            translations[element] = combined_element
                        else:
                            # add translation to the dictionary
                            # print(element)
                            translations[element] = translator.translate(
                                element, dest="en"
                            ).text
                        break
                    except AttributeError:
                        time.sleep(2)
                        print(f"Failed translating. Trying again. Try #{count}")
                        count += 1
                        continue
                    except Exception as e:
                        print("Failed translating. Not an attribute error")
                        print(e)
                        break

        df_en[column].replace(translations, inplace=True)
    return df_en
